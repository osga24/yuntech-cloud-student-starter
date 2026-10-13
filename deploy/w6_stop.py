#!/usr/bin/env python3
"""Stop only the recorded W5 EC2 and private RDS while preserving W6 IoT identities."""
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab

STATE = ROOT / ".local" / "resources.json"


def main():
    if not STATE.is_file():
        raise lab.LabError("Missing .local/resources.json; refusing to guess resource ownership.")
    ctx = lab.verify()
    data = json.loads(STATE.read_text(encoding="utf-8"))
    iid, dbid = data.get("instance_id", ""), data.get("w05_db_instance_identifier", "")
    gw_cert, consumer_cert = data.get("iot_gw_cert_id", ""), data.get("iot_consumer_cert_id", "")
    if not iid or not dbid or not gw_cert or not consumer_cert:
        raise lab.LabError("Recorded EC2, RDS, or W6 certificate identifiers are incomplete; stop and inspect.")
    instance = lab.run_aws(["ec2", "describe-instances", "--instance-ids", iid,
                            "--query", "Reservations[0].Instances[0].{Id:InstanceId,State:State.Name}"], ctx["region"])
    db = lab.run_aws(["rds", "describe-db-instances", "--db-instance-identifier", dbid,
                      "--query", "DBInstances[0].{Id:DBInstanceIdentifier,Status:DBInstanceStatus,Public:PubliclyAccessible}"], ctx["region"])
    if instance.get("Id") != iid or db.get("Id") != dbid or db.get("Public") is not False:
        raise lab.LabError("Resource read-back did not match the saved W5 IDs or private-RDS condition.")
    if instance.get("State") not in ("running", "stopped") or db.get("Status") not in ("available", "stopped"):
        raise lab.LabError(f"Resources are transitioning (EC2={instance.get('State')}, RDS={db.get('Status')}); wait and inspect before stopping.")
    statuses = {}
    for name, cert in (("gateway", gw_cert), ("consumer", consumer_cert)):
        result = lab.run_aws(["iot", "describe-certificate", "--certificate-id", cert], ctx["region"])
        statuses[name] = result["certificateDescription"]["status"]
    if set(statuses.values()) != {"ACTIVE"}:
        raise lab.LabError("W6 IoT certificates are not both ACTIVE; inspect before stopping the lab resources.")

    if instance["State"] == "running" or db["Status"] == "available":
        lab.approve(
            f"STOP only EC2 {iid} (currently {instance['State']}) and private RDS {dbid} "
            f"(currently {db['Status']}, PubliclyAccessible=false) in {ctx['region']}. "
            "No deletion; EBS/RDS storage, subnets, route table, DB subnet group, security groups, IoT certificates and policies remain. "
            "Stopping ends EC2/RDS compute use, while retained storage may continue to incur charges; RDS may automatically restart after 7 days. "
            f"Recovery: start these exact IDs again with deploy/w6-start.sh. IoT certificates remain ACTIVE. ",
            "STOP_W6",
        )
    if instance["State"] == "running":
        lab.run_aws(["ec2", "stop-instances", "--instance-ids", iid], ctx["region"])
    if db["Status"] == "available":
        lab.run_aws(["rds", "stop-db-instance", "--db-instance-identifier", dbid], ctx["region"])

    deadline = time.monotonic() + 900
    while True:
        ec2_state = lab.run_aws(["ec2", "describe-instances", "--instance-ids", iid,
                                 "--query", "Reservations[0].Instances[0].State.Name"], ctx["region"])
        rds_state = lab.run_aws(["rds", "describe-db-instances", "--db-instance-identifier", dbid,
                                 "--query", "DBInstances[0].DBInstanceStatus"], ctx["region"])
        if ec2_state == "stopped" and rds_state == "stopped":
            break
        if time.monotonic() >= deadline:
            raise lab.LabError(f"Stop wait exceeded 15 minutes (EC2={ec2_state}, RDS={rds_state}); recheck these IDs later.")
        time.sleep(10)
    print(json.dumps({"EC2": "stopped", "RDS": "stopped", "PubliclyAccessible": False,
                      "IoT_gateway_certificate": statuses["gateway"],
                      "IoT_consumer_certificate": statuses["consumer"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (lab.LabError, OSError, KeyError, ValueError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, lab.LabError) else type(exc).__name__), file=__import__("sys").stderr)
        raise SystemExit(1)
