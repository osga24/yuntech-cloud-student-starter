#!/usr/bin/env python3
"""Run the W5 five-row idempotency matrix against this student's EC2 service."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab


def read_env(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def request(base, method, path, token=None, payload=None):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        finally:
            exc.close()


def ssh(instance, key, command, timeout=30):
    opts = ["ssh", "-i", str(key), "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8", "-o", "BatchMode=yes"]
    result = subprocess.run(opts + [f"ec2-user@{instance}", command], capture_output=True,
                            text=True, timeout=timeout, check=False)
    if result.returncode:
        # Never show remote stderr; it can include service or connection details.
        raise RuntimeError("EC2 command failed; inspect the host locally without printing secrets.")
    return result.stdout.strip()


def main():
    local = ROOT / ".local"
    app_env = read_env(local / "app.env")
    if (local / "app.env").stat().st_mode & 0o777 != 0o600:
        raise RuntimeError(".local/app.env must have mode 600")
    reporter, operator = app_env.get("REPORTER_TOKEN", ""), app_env.get("OPERATOR_TOKEN", "")
    if not reporter or not operator or reporter == operator:
        raise RuntimeError("Reporter/operator credentials are not configured")
    ctx = lab.verify()
    resources = json.loads((local / "resources.json").read_text(encoding="utf-8"))
    instance_id = resources.get("instance_id")
    instance = lab.run_aws(["ec2", "describe-instances", "--instance-ids", instance_id,
                            "--query", "Reservations[0].Instances[0].{State:State.Name,IP:PublicIpAddress}"],
                           ctx["region"])
    if instance.get("State") != "running" or not instance.get("IP"):
        raise RuntimeError("Recorded EC2 instance is not running with a public address")
    if not resources.get("w05_db_instance_identifier") or not (local / "db.env").exists():
        raise RuntimeError("W5 database is not recorded/configured")
    if (local / "db.env").stat().st_mode & 0o777 != 0o600:
        raise RuntimeError(".local/db.env must have mode 600")

    base = "http://" + instance["IP"]
    status, health = request(base, "GET", "/health")
    if status != 200:
        raise RuntimeError("/health did not return HTTP 200")
    print(f"version={health.get('version')} db_configured={str(health.get('db_configured')).lower()}")
    if health.get("db_configured") is not True:
        raise RuntimeError("/health db_configured is not true")

    event_id = "g08-m2-w05-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", event_id):
        raise RuntimeError("Generated event_id is invalid")
    event = {"event_id": event_id, "device_id": "g08-m2-sensor", "observed_at":
             datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
             "type": "test", "note": "W5 idempotency matrix"}
    for number, body in ((1, event), (2, event), (3, {**event, "note": "W5 changed note"})):
        status, response = request(base, "POST", "/events", reporter, body)
        print(f"{number} HTTP {status} {json.dumps(response, ensure_ascii=False, separators=(',', ':'))}")

    key = Path(resources["private_key"])
    ssh(instance["IP"], key, "sudo systemctl restart inspection")
    detail = None
    for attempt in range(10):
        try:
            status, detail = request(base, "GET", "/events/" + event_id, operator)
            if status == 200:
                break
            if attempt == 9:
                raise RuntimeError("Event lookup after restart did not return HTTP 200")
        except (OSError, TimeoutError):
            if attempt == 9:
                raise RuntimeError("Service did not return after restart")
        time.sleep(2)
    print(f"4 HTTP {status} {json.dumps(detail, ensure_ascii=False, separators=(',', ':'))}")

    remote_script = ('set -a; . /etc/inspection/app.env; set +a; '
                     'PGPASSWORD="$DB_PASSWORD" psql "host=$DB_HOST dbname=$DB_NAME user=$DB_USER '
                     'sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem" '
                     '-v event_id="$1" -At <<\'SQL\'\n'
                     "SELECT count(*) FROM events WHERE event_id = :'event_id';\nSQL")
    remote_command = "sudo bash -c " + shlex.quote(remote_script) + " bash " + shlex.quote(event_id)
    count = ssh(instance["IP"], key, remote_command)
    if not re.fullmatch(r"\d+", count):
        raise RuntimeError("EC2 psql did not return a row count")
    print(f"5 psql_count={count}")


if __name__ == "__main__":
    try:
        main()
    except (lab.LabError, OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, lab.LabError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
