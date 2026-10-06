#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 INSTANCE_ID SSH_PRIVATE_KEY" >&2
  exit 2
fi
instance_id=$1
key_file=$2
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

secret=.local/app.env
temp_secret=""
secret_mode=$(stat -f '%Lp' "$secret" 2>/dev/null || stat -c '%a' "$secret" 2>/dev/null || true)
if [[ ! -f $secret || $secret_mode != 600 ]]; then
  echo "STOP: .local/app.env must exist and have mode 600." >&2
  exit 1
fi
[[ -f $key_file ]] || { echo "STOP: SSH private key not found." >&2; exit 1; }
db_secret=.local/db.env
if [[ -f $db_secret ]]; then
  db_mode=$(stat -f '%Lp' "$db_secret" 2>/dev/null || stat -c '%a' "$db_secret" 2>/dev/null || true)
  [[ $db_mode == 600 ]] || { echo "STOP: .local/db.env must have mode 600." >&2; exit 1; }
  temp_secret=$(mktemp .local/deploy-secret.XXXXXX)
  chmod 600 "$temp_secret"
  cat .local/app.env .local/db.env > "$temp_secret"
  secret=$temp_secret
fi
trap '[[ -z "$temp_secret" ]] || rm -f "$temp_secret"' EXIT

commit=$(git rev-parse --verify HEAD^{commit})
if [[ -n $(git status --porcelain -- app/service.py deploy/nginx.conf) ]]; then
  echo "STOP: app/service.py or deploy/nginx.conf has uncommitted changes." >&2
  exit 1
fi

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

echo "Target instance: $instance_id ($public_ip)"
echo "Committed version: $commit"
echo "Changes: install committed app/nginx files; install root-owned /etc/inspection/app.env (600); restart inspection."
echo "Exposure: no Security Group changes; existing TCP 22/80 rules remain unchanged."
echo "Cost: no new AWS resource; the running EC2, EBS, and public IPv4 continue incurring Learner Lab usage."
echo "Recovery: rerun this script with an earlier committed SHA checked out, or use the reviewed W3 down.sh for owned resource IDs."
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
  'sudo install -d -m 755 /etc/inspection && sudo install -o root -g root -m 600 /dev/stdin /etc/inspection/app.env && sudo systemctl restart inspection' \
  < "$secret"

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
