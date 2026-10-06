#!/usr/bin/env python3
"""Create this student's private W5 PostgreSQL resources using the lab wrapper."""
import json
import ipaddress
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab

LOCAL = ROOT / ".local"
RESOURCES = LOCAL / "resources.json"
REGION = "us-east-1"
VPC = "vpc-05f5a4c03b646d98a"
HOST_SG = "sg-08322f90f9480e984"
DB_ID = "yuntech-w05-g08-m2-db"
DB_SG_NAME = "yuntech-w05-g08-m2-db"
SUBNET_GROUP = "yuntech-w05-g08-m2-db"
TAGS = [
    {"Key": "course", "Value": "yuntech-115-1"},
    {"Key": "week", "Value": "w05"},
    {"Key": "group", "Value": "g08"},
    {"Key": "owner", "Value": "m2"},
]


def load_resources():
    data = json.loads(RESOURCES.read_text(encoding="utf-8"))
    if data.get("region") != REGION or data.get("vpc_id") != VPC or data.get("security_group_id") != HOST_SG:
        raise lab.LabError(".local/resources.json context differs from the reviewed W5 target; stop and reconcile first.")
    return data


def save_resources(data):
    lab.atomic_write(RESOURCES, json.dumps(data, indent=2) + "\n")


def query(args):
    return lab.run_aws(args, REGION)


def tag_spec(resource_type):
    tags = ",".join("{Key=%s,Value=%s}" % (tag["Key"], tag["Value"]) for tag in TAGS)
    return f"ResourceType={resource_type},Tags=[{tags}]"


def ensure_subnet(data, key, cidr, az):
    if data.get(key):
        result = query(["ec2", "describe-subnets", "--subnet-ids", data[key], "--query",
                        "Subnets[0].{Vpc:VpcId,Cidr:CidrBlock,AZ:AvailabilityZone}"])
        if result != {"Vpc": VPC, "Cidr": cidr, "AZ": az}:
            raise lab.LabError(f"Recorded {key} does not match the reviewed subnet plan.")
        return data[key]
    result = query(["ec2", "create-subnet", "--vpc-id", VPC, "--cidr-block", cidr,
                    "--availability-zone", az, "--tag-specifications", tag_spec("subnet")])
    subnet_id = result["Subnet"]["SubnetId"]
    data[key] = subnet_id
    save_resources(data)
    return subnet_id


def ensure_route_table(data):
    if data.get("w05_route_table_id"):
        rt_id = data["w05_route_table_id"]
        result = query(["ec2", "describe-route-tables", "--route-table-ids", rt_id,
                        "--query", "RouteTables[0].{Vpc:VpcId,Routes:Routes[].DestinationCidrBlock}"])
        if result.get("Vpc") != VPC or set(result.get("Routes", [])) != {"172.31.0.0/16"}:
            raise lab.LabError("Recorded W5 route table is not the expected local-only table.")
        return rt_id
    result = query(["ec2", "create-route-table", "--vpc-id", VPC,
                    "--tag-specifications", tag_spec("route-table")])
    rt_id = result["RouteTable"]["RouteTableId"]
    data["w05_route_table_id"] = rt_id
    save_resources(data)
    return rt_id


def ensure_association(rt_id, subnet_id):
    data = load_resources()
    current = query(["ec2", "describe-route-tables", "--route-table-ids", rt_id,
                     "--query", "RouteTables[0].Associations[].SubnetId"])
    if subnet_id not in current:
        result = query(["ec2", "associate-route-table", "--route-table-id", rt_id,
                        "--subnet-id", subnet_id])
        slot = "w05_route_association_a_id" if subnet_id == data["w05_private_subnet_a"] else "w05_route_association_b_id"
        data[slot] = result["AssociationId"]
        save_resources(data)


def ensure_db_sg(data):
    if data.get("w05_db_security_group_id"):
        sg_id = data["w05_db_security_group_id"]
        groups = query(["ec2", "describe-security-groups", "--group-ids", sg_id,
                        "--query", "SecurityGroups[0].{Vpc:VpcId,Name:GroupName,Ingress:IpPermissions}"])
        if groups.get("Vpc") != VPC or groups.get("Name") != DB_SG_NAME:
            raise lab.LabError("Recorded W5 DB security group does not match the expected VPC/name.")
        perms = groups.get("Ingress", [])
        expected = (len(perms) == 1 and perms[0].get("IpProtocol") == "tcp"
                    and perms[0].get("FromPort") == 5432 and perms[0].get("ToPort") == 5432
                    and [p.get("GroupId") for p in perms[0].get("UserIdGroupPairs", [])] == [HOST_SG]
                    and not perms[0].get("IpRanges") and not perms[0].get("Ipv6Ranges")
                    and not perms[0].get("PrefixListIds"))
        if perms and not expected:
            raise lab.LabError("Recorded W5 DB SG has unexpected ingress; inspect manually, no rule was changed.")
        if not perms:
            add_host_sg_rule(sg_id)
        return sg_id
    result = query(["ec2", "create-security-group", "--group-name", DB_SG_NAME,
                    "--description", "W5 private RDS SG for g08 m2",
                    "--vpc-id", VPC, "--tag-specifications", tag_spec("security-group")])
    sg_id = result["GroupId"]
    data["w05_db_security_group_id"] = sg_id
    save_resources(data)
    add_host_sg_rule(sg_id)
    return sg_id


def add_host_sg_rule(sg_id):
    permissions = [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                    "UserIdGroupPairs": [{"GroupId": HOST_SG}]}]
    query(["ec2", "authorize-security-group-ingress", "--group-id", sg_id,
           "--ip-permissions", json.dumps(permissions, separators=(",", ":"))])


def ensure_subnet_group(data, subnet_ids):
    if not data.get("w05_db_subnet_group"):
        query(["rds", "create-db-subnet-group", "--db-subnet-group-name", SUBNET_GROUP,
               "--db-subnet-group-description", "W5 private RDS subnets for g08 m2",
               "--subnet-ids", *subnet_ids, "--tags", *[f"Key={t['Key']},Value={t['Value']}" for t in TAGS]])
        data["w05_db_subnet_group"] = SUBNET_GROUP
        save_resources(data)


def write_db_env(host, password):
    content = (f"DB_HOST={host}\nDB_NAME=inspection\nDB_USER=inspection_admin\nDB_PASSWORD={password}\n")
    lab.atomic_write(LOCAL / "db.env", content)


def wait_available():
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        item = query(["rds", "describe-db-instances", "--db-instance-identifier", DB_ID,
                      "--query", "DBInstances[0].{Status:DBInstanceStatus,Public:PubliclyAccessible,Endpoint:Endpoint.Address}"])
        if item.get("Status") == "available":
            if item.get("Public") is not False or not item.get("Endpoint"):
                raise lab.LabError("RDS read-back failed PubliclyAccessible=false or endpoint validation.")
            return item["Endpoint"]
        if item.get("Status") in ("failed", "incompatible-parameters", "incompatible-restore"):
            raise lab.LabError(f"RDS entered terminal status {item['Status']}; inspect before retrying.")
        print(f"RDS status: {item.get('Status', 'unknown')} (waiting)")
        time.sleep(30)
    raise lab.LabError("RDS did not become available within 20 minutes; inspect before retrying.")


def main():
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    ctx = lab.verify()
    if ctx["region"] != REGION:
        raise lab.LabError("Verified region is not the reviewed us-east-1 target.")
    data = load_resources()
    subnets = query(["ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={VPC}",
                     "--query", "Subnets[].{Cidr:CidrBlock,AZ:AvailabilityZone}"])
    existing = [row["Cidr"] for row in subnets]
    planned = (("w05_private_subnet_a", ipaddress.ip_network("172.31.96.0/24")),
               ("w05_private_subnet_b", ipaddress.ip_network("172.31.97.0/24")))
    for key, candidate in planned:
        if not data.get(key) and any(candidate.overlaps(ipaddress.ip_network(cidr)) for cidr in existing):
            raise lab.LabError(f"Candidate CIDR {candidate} overlaps an existing subnet; reconcile before continuing.")
    one = ensure_subnet(data, "w05_private_subnet_a", "172.31.96.0/24", "us-east-1a")
    two = ensure_subnet(data, "w05_private_subnet_b", "172.31.97.0/24", "us-east-1b")
    route_table = ensure_route_table(data)
    ensure_association(route_table, one)
    ensure_association(route_table, two)
    sg_id = ensure_db_sg(data)
    ensure_subnet_group(data, [one, two])

    dbs = query(["rds", "describe-db-instances", "--query",
                 "DBInstances[?DBInstanceIdentifier=='" + DB_ID + "'].{Status:DBInstanceStatus,Public:PubliclyAccessible}"])
    if not data.get("w05_db_instance_identifier"):
        if dbs:
            raise lab.LabError("RDS identifier exists but is not recorded in .local/resources.json; verify ownership first.")
        password = secrets.token_urlsafe(36)
        write_db_env("pending", password)
        config = {
            "DBInstanceIdentifier": DB_ID, "Engine": "postgres", "DBInstanceClass": "db.t3.micro",
            "AllocatedStorage": 20, "StorageType": "gp3", "StorageEncrypted": True,
            "PubliclyAccessible": False, "MultiAZ": False, "DBName": "inspection",
            "MasterUsername": "inspection_admin", "MasterUserPassword": password,
            "DBSubnetGroupName": SUBNET_GROUP, "VpcSecurityGroupIds": [sg_id],
            "BackupRetentionPeriod": 1, "AutoMinorVersionUpgrade": True,
            "Tags": TAGS,
        }
        fd, filename = tempfile.mkstemp(prefix=".w05-rds-", suffix=".json", dir=LOCAL)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(config, stream)
            query(["rds", "create-db-instance", "--cli-input-json", "file://" + filename])
        finally:
            Path(filename).unlink(missing_ok=True)
        data["w05_db_instance_identifier"] = DB_ID
        save_resources(data)
    elif not (LOCAL / "db.env").exists():
        raise lab.LabError("RDS is recorded but .local/db.env is missing; refusing to rotate the DB password automatically.")

    if (LOCAL / "db.env").exists():
        endpoint = wait_available()
        text = (LOCAL / "db.env").read_text(encoding="utf-8")
        lines = [line for line in text.splitlines() if not line.startswith("DB_HOST=")]
        lines.insert(0, "DB_HOST=" + endpoint)
        lab.atomic_write(LOCAL / "db.env", "\n".join(lines) + "\n")
    data["w05_db_endpoint"] = query(["rds", "describe-db-instances", "--db-instance-identifier", DB_ID,
                                     "--query", "DBInstances[0].Endpoint.Address"])
    save_resources(data)
    final = query(["rds", "describe-db-instances", "--db-instance-identifier", DB_ID,
                   "--query", "DBInstances[0].{Id:DBInstanceIdentifier,Status:DBInstanceStatus,PubliclyAccessible:PubliclyAccessible}"])
    if final.get("Status") != "available" or final.get("PubliclyAccessible") is not False:
        raise lab.LabError("Final RDS read-back did not satisfy available/private requirements.")
    print(json.dumps({"RDS": {"IdSuffix": final["Id"][-4:], "Status": final["Status"],
                               "PubliclyAccessible": final["PubliclyAccessible"]},
                      "PrivateSubnets": [one, two], "RouteTable": route_table,
                      "DBSecurityGroup": sg_id}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (lab.LabError, OSError, KeyError, ValueError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, lab.LabError) else type(exc).__name__), file=__import__("sys").stderr)
        raise SystemExit(1)
