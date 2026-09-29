#!/usr/bin/env python3
"""Run the seven W4 rejection-matrix requests without printing tokens."""
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab  # noqa: E402


def secrets(path):
    if path.stat().st_mode & 0o077:
        raise SystemExit("STOP: .local/app.env must have mode 600")
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    if not values.get("REPORTER_TOKEN") or not values.get("OPERATOR_TOKEN"):
        raise SystemExit("STOP: secret file is missing the two required tokens")
    return values


def request(base, method, path, token=None, body=None):
    headers, data = {}, None
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    with response:
        return response.status, response.read().decode()


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit(f"Usage: {sys.argv[0]} INSTANCE_ID [BASE_URL]")
    ctx = lab.verify()
    item = lab.run_aws(["ec2", "describe-instances", "--instance-ids", sys.argv[1],
                        "--query", "Reservations[0].Instances[0].{State:State.Name,IP:PublicIpAddress}"], ctx["region"])
    if item.get("State") != "running" or not item.get("IP"):
        raise SystemExit("STOP: target must be running with a public IPv4 address")
    base = sys.argv[2].rstrip("/") if len(sys.argv) == 3 else "http://" + item["IP"]
    token = secrets(ROOT / ".local/app.env")
    event = json.loads((ROOT / "tests/fixtures/valid_event.json").read_text())
    no_timezone = dict(event, event_id=event["event_id"] + "-tz", observed_at="2026-09-29T10:00:00")

    health_status, health_body = request(base, "GET", "/health")
    if health_status != 200:
        raise SystemExit(f"STOP: health returned HTTP {health_status}")
    print("version=" + json.loads(health_body)["version"])
    cases = [
        ("POST", "/events", token["REPORTER_TOKEN"], event),
        ("POST", "/events", None, event),
        ("POST", "/events", token["OPERATOR_TOKEN"], event),
        ("POST", "/events", token["REPORTER_TOKEN"], no_timezone),
        ("POST", "/events", token["REPORTER_TOKEN"], event),
        ("GET", "/events", token["REPORTER_TOKEN"], None),
        ("GET", "/events", token["OPERATOR_TOKEN"], None),
    ]
    expected = [201, 401, 403, 400, 409, 403, 200]
    failed = False
    for number, (case, want) in enumerate(zip(cases, expected), 1):
        status, body = request(base, *case)
        print(f"#{number} HTTP {status} {body}")
        failed |= status != want
    if failed:
        raise SystemExit("STOP: one or more rows differed from the public contract")


if __name__ == "__main__":
    main()
