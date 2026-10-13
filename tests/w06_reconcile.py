#!/usr/bin/env python3
"""Reconcile one W6 MQTT run against consumer logs, RDS, and the filtered API."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
CODE_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
DIRECT_HTTP = build_opener(ProxyHandler({}))


def read_env(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def ssh_capture(key, host, command):
    return subprocess.run(
        ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ConnectTimeout=10", f"ec2-user@{host}", command],
        text=True, capture_output=True, timeout=25, check=False,
    )


def remote_snapshot(key, host, prefix):
    quoted_prefix = shlex.quote(prefix + "-")
    command = (
        "sudo journalctl -u inspection-consumer -o cat --no-pager "
        f"| grep -F 'event_id={prefix}-' | grep -o 'result=[a-z]*' | sort | uniq -c || true; "
        "sudo bash -c " + shlex.quote(
            "set -a; . /etc/inspection/app.env; set +a; "
            'PGCONNECT_TIMEOUT=5 PGPASSWORD="$DB_PASSWORD" psql "host=$DB_HOST dbname=$DB_NAME user=$DB_USER '
            'sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem" '
            f"-v prefix={quoted_prefix} -At -v ON_ERROR_STOP=1 "
            "-c \"SELECT count(*) FROM events WHERE left(event_id, length(:'prefix')) = :'prefix';\""
        )
    )
    return ssh_capture(key, host, command)


def sample_logs(key, host, prefix):
    command = (
        "sudo journalctl -u inspection-consumer -o cat --no-pager "
        f"| grep -E 'event_id={prefix}-d(01-01|99-01) ' || true"
    )
    return ssh_capture(key, host, command)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    if not CODE_RE.fullmatch(args.code) or not CODE_RE.fullmatch(args.run):
        parser.error("--code and --run must match ^[A-Za-z0-9-]{1,40}$")
    prefix = f"{args.code}-{args.run}"

    resource_path = ROOT / ".local" / "resources.json"
    run_path = ROOT / ".local" / "w06-last-run.json"
    env_path = ROOT / ".local" / "app.env"
    resources = json.loads(resource_path.read_text(encoding="utf-8"))
    last_run = json.loads(run_path.read_text(encoding="utf-8"))
    if last_run.get("prefix") != prefix:
        raise SystemExit("STOP: requested prefix does not match .local/w06-last-run.json")
    app_env = read_env(env_path)
    token = app_env.get("OPERATOR_TOKEN", "")
    if not token:
        raise SystemExit("STOP: OPERATOR_TOKEN missing from .local/app.env")
    host = resources.get("public_ip", "")
    key_path = Path(resources.get("private_key", ""))
    if not key_path.is_file():
        key_path = ROOT / ".local" / key_path.name
    if not host or not key_path.is_file():
        raise SystemExit("STOP: host address or SSH key path is unavailable in local W3 resources")

    try:
        with DIRECT_HTTP.open(f"http://{host}/health", timeout=10) as response:
            health = json.load(response)
    except (URLError, TimeoutError, HTTPError) as exc:
        raise SystemExit(f"STOP: cannot read /health ({type(exc).__name__})") from None
    print(f"version={health.get('version')} db_configured={str(health.get('db_configured')).lower()} prefix={prefix}")
    print(f"puback_ok={last_run.get('puback_ok')}/32")

    snapshot = None
    deadline = time.monotonic() + 60
    while time.monotonic() <= deadline:
        snapshot = remote_snapshot(str(key_path), host, prefix)
        if snapshot.returncode == 0:
            counters = {name: 0 for name in ("created", "duplicate", "rejected", "error")}
            db_count = None
            for line in snapshot.stdout.splitlines():
                match = re.fullmatch(r"\s*(\d+)\s+(created|duplicate|rejected|error)", line)
                if match:
                    counters[match.group(2)] += int(match.group(1))
                elif line.strip().isdigit():
                    db_count = int(line.strip())
            if db_count is not None and sum(counters.values()) >= 32:
                break
        time.sleep(5)
    if snapshot is None or snapshot.returncode != 0:
        raise SystemExit("STOP: SSH reconciliation failed; inspect SSH access and remote services")
    if db_count is None:
        raise SystemExit("STOP: psql count missing; inspect the remote command result without printing secrets")
    print("consumer=" + json.dumps(counters, separators=(",", ":")))
    print(f"database_count={db_count}")
    evidence = sample_logs(str(key_path), host, prefix)
    if evidence.returncode != 0:
        raise SystemExit("STOP: could not read the required consumer evidence logs")
    print("consumer_evidence_begin")
    print(evidence.stdout.rstrip())
    print("consumer_evidence_end")

    url = f"http://{host}/events?{urlencode({'device_id': args.code + '-d01'})}"
    request = Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with DIRECT_HTTP.open(request, timeout=10) as response:
            events = json.load(response)
    except (URLError, TimeoutError, HTTPError) as exc:
        raise SystemExit(f"STOP: filtered API request failed ({type(exc).__name__})") from None
    matched = [event.get("event_id") for event in events
               if isinstance(event, dict) and str(event.get("event_id", "")).startswith(prefix + "-")]
    print("device_d01_event_ids=" + json.dumps(matched, separators=(",", ":")))
    print(f"device_d01_prefix_count={len(matched)}")


if __name__ == "__main__":
    main()
