#!/usr/bin/env python3
"""Resume recorded W5 EC2/RDS and align SSH/HTTP ingress to this Mac's /32."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab

STATE = ROOT / ".local" / "resources.json"


def save(data):
    lab.atomic_write(STATE, json.dumps(data, indent=2) + "\n")


def mac_cidr():
    result = subprocess.run(["curl", "--noproxy", "*", "--max-time", "8", "-fsS",
                             "https://checkip.amazonaws.com"],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        raise lab.LabError("Could not determine the Mac's current public egress IP; refusing security-group changes.")
    value = result.stdout.strip()
    ipaddress.IPv4Address(value)
    return value + "/32"


def inbound_sources(ctx, sg_id):
    sg = lab.run_aws(["ec2", "describe-security-groups", "--group-ids", sg_id], ctx["region"])["SecurityGroups"][0]
    if sg.get("GroupId") != sg_id:
        raise lab.LabError("Recorded security group could not be read back; refusing network changes.")
    result = {}
    for port in (22, 80):
        matching = [perm for perm in sg.get("IpPermissions", [])
                    if perm.get("IpProtocol") == "tcp" and perm.get("FromPort") == port and perm.get("ToPort") == port]
        if len(matching) != 1 or matching[0].get("UserIdGroupPairs") or matching[0].get("Ipv6Ranges") or matching[0].get("PrefixListIds"):
            raise lab.LabError(f"Security group TCP/{port} rule is not the expected single IPv4 CIDR; inspect manually.")
        result[port] = {item["CidrIp"] for item in matching[0].get("IpRanges", [])}
        if len(result[port]) != 1:
            raise lab.LabError(f"Security group TCP/{port} must have exactly one IPv4 source; refusing changes.")
    return result


def set_mac_source(ctx, data, target):
    sg_id = data.get("security_group_id", "")
    if not sg_id:
        raise lab.LabError("Recorded host security group missing from resources file.")
    sources = inbound_sources(ctx, sg_id)
    if all(values == {target} for values in sources.values()):
        data["source_cidr"] = target
        save(data)
        return
    old = data.get("source_cidr", "")
    if not old or any(values not in ({old}, {target}) for values in sources.values()):
        raise lab.LabError("Recorded source CIDR does not match actual TCP/22 and TCP/80 rules; refusing to guess ownership.")
    plan = (
        f"Change only SG {sg_id}: TCP 22 and 80 source {old} -> {target}. "
        "The new source is this Mac's current public IPv4 /32; no broad ingress, no other ports, no new AWS resource. "
        "No hourly resource cost change; EC2/RDS runtime charges continue while started. "
        f"Recovery: restore TCP 22 and 80 to {old} in the same recorded SG."
    )
    lab.approve(plan, "UPDATE_SG")
    for port in (22, 80):
        if sources[port] != {target}:
            permission = [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                           "IpRanges": [{"CidrIp": target, "Description": "W6 Mac /32"}]}]
            lab.run_aws(["ec2", "authorize-security-group-ingress", "--group-id", sg_id,
                         "--ip-permissions", json.dumps(permission)], ctx["region"])
    for port in (22, 80):
        if sources[port] == {old}:
            permission = [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                           "IpRanges": [{"CidrIp": old}]}]
            lab.run_aws(["ec2", "revoke-security-group-ingress", "--group-id", sg_id,
                         "--ip-permissions", json.dumps(permission)], ctx["region"])
    data["source_cidr"] = target
    save(data)
    verified = inbound_sources(ctx, sg_id)
    if any(values != {target} for values in verified.values()):
        raise lab.LabError("Final security-group read-back differs from the requested /32; stop and inspect.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-cidr", help="explicit Mac SSH/HTTP egress IPv4 /32")
    args = parser.parse_args()
    if not STATE.is_file():
        raise lab.LabError("Missing .local/resources.json; W6 must resume the recorded W5 resources.")
    ctx = lab.verify()
    data = json.loads(STATE.read_text(encoding="utf-8"))
    if data.get("region") != ctx["region"] or ctx["region"] != "us-east-1":
        raise lab.LabError("Recorded W5 resource region does not match this us-east-1 Learner Lab context.")
    instance_id = data.get("instance_id", "")
    db_id = data.get("w05_db_instance_identifier", "")
    if not instance_id or not db_id:
        raise lab.LabError("Recorded W5 EC2 or RDS identifier missing; refusing to create replacement resources.")
    if args.source_cidr:
        try:
            network = ipaddress.ip_network(args.source_cidr, strict=True)
        except ValueError as exc:
            raise lab.LabError("--source-cidr must be a valid IPv4 /32.") from exc
        if network.version != 4 or network.prefixlen != 32:
            raise lab.LabError("--source-cidr must be a valid IPv4 /32.")
        target = str(network)
    else:
        target = mac_cidr()

    instance = lab.run_aws(["ec2", "describe-instances", "--instance-ids", instance_id,
                            "--query", "Reservations[0].Instances[0].{Id:InstanceId,State:State.Name}"], ctx["region"])
    db = lab.run_aws(["rds", "describe-db-instances", "--db-instance-identifier", db_id,
                      "--query", "DBInstances[0].{Id:DBInstanceIdentifier,Status:DBInstanceStatus,Public:PubliclyAccessible}"], ctx["region"])
    if instance.get("Id") != instance_id or db.get("Id") != db_id or db.get("Public") is not False:
        raise lab.LabError("Recorded EC2/RDS ownership or private-RDS read-back did not match; stop before changing anything.")
    if instance.get("State") not in ("stopped", "running"):
        raise lab.LabError(f"EC2 is {instance.get('State')}; inspect before proceeding.")
    if db.get("Status") not in ("stopped", "available", "starting"):
        raise lab.LabError(f"RDS is {db.get('Status')}; inspect before proceeding.")

    if instance["State"] == "stopped" or db["Status"] == "stopped":
        plan = (
            f"START only recorded EC2 {instance_id} and/or private RDS {db_id} in {ctx['region']} "
            f"(EC2={instance['State']}, RDS={db['Status']}, PubliclyAccessible=false). "
            "No new AWS resource and no database/host replacement. EC2 compute, EBS, public IPv4 and RDS compute/storage "
            "are billable while active; stop both at W6 T4. Recovery: stop these same two recorded IDs."
        )
        lab.approve(plan, "START_W6")
    if instance["State"] == "stopped":
        lab.run_aws(["ec2", "start-instances", "--instance-ids", instance_id], ctx["region"])
    if db["Status"] == "stopped":
        lab.run_aws(["rds", "start-db-instance", "--db-instance-identifier", db_id], ctx["region"])

    if instance["State"] == "stopped":
        lab.run_aws(["ec2", "wait", "instance-running", "--instance-ids", instance_id], ctx["region"])
    current_ip = None
    for _ in range(12):
        value = lab.run_aws(["ec2", "describe-instances", "--instance-ids", instance_id,
                             "--query", "Reservations[0].Instances[0].{State:State.Name,IP:PublicIpAddress}"], ctx["region"])
        if value.get("State") == "running" and value.get("IP"):
            current_ip = value["IP"]
            break
        time.sleep(5)
    if not current_ip:
        raise lab.LabError("EC2 did not return to running with a public IPv4; inspect recorded instance.")
    data["public_ip"] = current_ip
    save(data)

    set_mac_source(ctx, data, target)
    deadline = time.monotonic() + 900
    while True:
        db_state = lab.run_aws(["rds", "describe-db-instances", "--db-instance-identifier", db_id,
                                "--query", "DBInstances[0].DBInstanceStatus"], ctx["region"])
        if db_state == "available":
            break
        if time.monotonic() >= deadline:
            raise lab.LabError(f"RDS did not become available within 15 minutes (last state {db_state}).")
        if db_state not in ("starting", "backing-up", "modifying"):
            raise lab.LabError(f"RDS entered unexpected state {db_state}; stop and inspect.")
        time.sleep(10)

    health = None
    for _ in range(24):
        try:
            with urllib.request.urlopen(f"http://{current_ip}/health", timeout=8) as response:
                health = json.load(response)
            if health.get("status") == "ok" and health.get("db_configured") is True:
                break
        except (OSError, ValueError):
            pass
        time.sleep(5)
    if not health or health.get("status") != "ok" or health.get("db_configured") is not True:
        raise lab.LabError("Host /health did not confirm the W5 API and DB after resume; inspect without creating replacements.")
    print(json.dumps({"EC2": "running", "RDS": "available", "PubliclyAccessible": False,
                      "host": current_ip, "health_version": health.get("version"), "MacSource": target}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (lab.LabError, OSError, KeyError, ValueError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, lab.LabError) else type(exc).__name__), file=__import__("sys").stderr)
        raise SystemExit(1)
