#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
use_recorded_ip=false
if [[ $# -eq 1 && $1 == --use-recorded-ip ]]; then
  use_recorded_ip=true
  IFS=$'\t' read -r instance_id key_file public_ip < <(python3 - <<'PY'
import ipaddress, json
from pathlib import Path
data = json.loads(Path(".local/resources.json").read_text())
key = Path(data.get("private_key", ""))
if not key.is_file():
    key = Path(".local") / key.name
ip = data.get("public_ip", "")
ipaddress.IPv4Address(ip)
print(data.get("instance_id", "") + "\t" + str(key) + "\t" + ip)
PY
  )
elif [[ $# -eq 0 ]]; then
  IFS=$'\t' read -r instance_id key_file < <(python3 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path(".local/resources.json").read_text())
key = Path(data.get("private_key", ""))
if not key.is_file():
    key = Path(".local") / key.name
print(data.get("instance_id", "") + "\t" + str(key))
PY
  )
elif [[ $# -eq 2 ]]; then
  instance_id=$1
  key_file=$2
else
  echo "Usage: $0 [INSTANCE_ID SSH_PRIVATE_KEY]" >&2
  exit 2
fi
[[ -n ${instance_id:-} && -n ${key_file:-} ]] || { echo "STOP: instance_id or SSH key path missing from .local/resources.json." >&2; exit 1; }

secret=.local/app.env
temp_secret=""
secret_mode=$(stat -f '%Lp' "$secret" 2>/dev/null || stat -c '%a' "$secret" 2>/dev/null || true)
if [[ ! -f $secret || $secret_mode != 600 ]]; then
  echo "STOP: .local/app.env must exist and have mode 600." >&2
  exit 1
fi
[[ -f $key_file ]] || { echo "STOP: SSH private key not found." >&2; exit 1; }
db_secret=.local/db.env
[[ -f $db_secret ]] || { echo "STOP: .local/db.env is required for W6." >&2; exit 1; }
db_mode=$(stat -f '%Lp' "$db_secret" 2>/dev/null || stat -c '%a' "$db_secret" 2>/dev/null || true)
[[ $db_mode == 600 ]] || { echo "STOP: .local/db.env must have mode 600." >&2; exit 1; }
iot_dir=.local/iot
for file in endpoint AmazonRootCA1.pem consumer.cert.pem consumer.private.key; do
  [[ -f $iot_dir/$file ]] || { echo "STOP: missing $iot_dir/$file." >&2; exit 1; }
  mode=$(stat -f '%Lp' "$iot_dir/$file" 2>/dev/null || stat -c '%a' "$iot_dir/$file" 2>/dev/null || true)
  [[ $mode == 600 ]] || { echo "STOP: $iot_dir/$file must have mode 600." >&2; exit 1; }
done
dir_mode=$(stat -f '%Lp' "$iot_dir" 2>/dev/null || stat -c '%a' "$iot_dir" 2>/dev/null || true)
[[ $dir_mode == 700 ]] || { echo "STOP: $iot_dir must have mode 700." >&2; exit 1; }
temp_secret=$(mktemp .local/deploy-secret.XXXXXX)
chmod 600 "$temp_secret"
trap '[[ -z "$temp_secret" ]] || rm -f "$temp_secret"' EXIT
cat .local/app.env .local/db.env > "$temp_secret"
python3 - "$temp_secret" "$iot_dir" <<'PY'
import json, sys
from pathlib import Path
secret = Path(sys.argv[1])
iot = Path(sys.argv[2])
data = json.loads(Path(".local/resources.json").read_text())
endpoint = (iot / "endpoint").read_text().strip()
if not endpoint or any(ch.isspace() for ch in endpoint):
    raise SystemExit("STOP: invalid IoT endpoint file")
code = "g08-m2"
values = {
    "IOT_ENDPOINT": endpoint,
    "IOT_TOPIC": f"cxe/{code}/gw/events",
    "IOT_CLIENT_ID": f"consumer-{code}",
    "IOT_DEVICE_IDS": ",".join(f"{code}-d{i:02d}" for i in range(1, 11)),
    "IOT_CA": "/etc/inspection/iot/AmazonRootCA1.pem",
    "IOT_CERT": "/etc/inspection/iot/consumer.cert.pem",
    "IOT_KEY": "/etc/inspection/iot/consumer.private.key",
}
if not data.get("iot_consumer_cert_id") or not data.get("iot_consumer_policy"):
    raise SystemExit("STOP: consumer certificate or policy ID missing from .local/resources.json")
env = {}
for line in secret.read_text(encoding="utf-8").splitlines():
    if line and not line.lstrip().startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        env[key.strip()] = value
required = ("REPORTER_TOKEN", "DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
if any(not env.get(key) for key in required):
    raise SystemExit("STOP: required app or database configuration is missing from local env files")
with secret.open("a", encoding="utf-8") as stream:
    stream.write("\n" + "".join(f"{key}={value}\n" for key, value in values.items()))
PY
secret=$temp_secret

commit=$(git rev-parse --verify HEAD^{commit})
if [[ -n $(git status --porcelain -- app/service.py app/consumer.py deploy/deploy.sh tools/iot_common.py tools/mqtt_check.py tools/gateway_sim.py tests/w06_reconcile.py) ]]; then
  echo "STOP: W6 application, tools, or deployment files have uncommitted changes." >&2
  exit 1
fi

if [[ $use_recorded_ip == true ]]; then
  [[ -n ${public_ip:-} ]] || { echo "STOP: recorded public IP missing from .local/resources.json." >&2; exit 1; }
else
public_ip=$(python3 - "$instance_id" <<'PY'
import sys
from scripts import lab
ctx = lab.verify()
item = lab.run_aws(["ec2", "describe-instances", "--instance-ids", sys.argv[1],
                    "--query", "Reservations[0].Instances[0].{State:State.Name,IP:PublicIpAddress}"], ctx["region"])
if item.get("State") != "running" or not item.get("IP"):
    raise lab.LabError("Target instance must be running and have a public IPv4 address.")
print(item["IP"])
PY
)
public_ip=$(printf '%s\n' "$public_ip" | tail -n 1)
fi

echo "Target instance: $instance_id ($public_ip)"
echo "Committed version: $commit"
echo "Changes: install committed app/consumer/nginx files; install root-owned /etc/inspection/app.env (600) and inspection-owned IoT certs (600); restart inspection and inspection-consumer."
echo "Exposure: no Security Group changes; existing TCP 22/80 rules remain unchanged."
echo "Cost: no new AWS resource; the running EC2, EBS, and public IPv4 continue incurring Learner Lab usage."
echo "Recovery: rerun this script with an earlier committed SHA checked out; remove only /etc/inspection/iot files and stop inspection-consumer to disable W6."
read -r -p "Type DEPLOY to continue: " answer
[[ $answer == DEPLOY ]] || { echo "Cancelled."; exit 1; }

mkdir -p .local
install_dir=$(mktemp -d .local/w04-install.XXXXXX)
install_script=$install_dir/install.sh
trap 'rm -rf "$install_dir"; [[ -z "$temp_secret" ]] || rm -f "$temp_secret"' EXIT
python3 deploy/make_user_data.py "$commit" "$install_script"
ssh_opts=(-i "$key_file" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8)
ssh "${ssh_opts[@]}" "ec2-user@$public_ip" 'sudo bash -s' < "$install_script"
ssh "${ssh_opts[@]}" "ec2-user@$public_ip" \
  'sudo install -d -o root -g root -m 755 /etc/inspection && sudo install -d -o inspection -g inspection -m 700 /etc/inspection/iot'
tar -czf - -C "$iot_dir" AmazonRootCA1.pem consumer.cert.pem consumer.private.key |
  ssh "${ssh_opts[@]}" "ec2-user@$public_ip" \
    'sudo tar --no-same-owner -xz -C /etc/inspection/iot && sudo sh -c "chown inspection:inspection /etc/inspection/iot/* && chmod 600 /etc/inspection/iot/* && chmod 755 /etc/inspection"'
ssh "${ssh_opts[@]}" "ec2-user@$public_ip" \
  'sudo install -d -m 755 /etc/inspection && sudo install -o root -g root -m 600 /dev/stdin /etc/inspection/app.env && sudo systemctl restart inspection' \
  < "$secret"
ssh "${ssh_opts[@]}" "ec2-user@$public_ip" \
  'sudo systemctl restart inspection-consumer && systemctl is-active inspection inspection-consumer'

health=$(ssh "${ssh_opts[@]}" "ec2-user@$public_ip" 'curl -fsS http://127.0.0.1/health')
db_expected=false
[[ -f .local/db.env ]] && db_expected=true
python3 - "$commit" "$health" "$db_expected" <<'PY'
import json, sys
body = json.loads(sys.argv[2])
expected_db = sys.argv[3] == "true"
if (body.get("version") != sys.argv[1] or body.get("auth_configured") is not True
        or body.get("db_configured") is not expected_db):
    raise SystemExit("STOP: /health did not confirm the commit, auth, and expected DB configuration")
print(json.dumps(body, separators=(",", ":")))
PY
