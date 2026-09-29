#!/usr/bin/env python3
"""Create/stop/delete only the course-owned W3 EC2 resources."""
import argparse, json, os, subprocess, sys, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab  # noqa: E402
from deploy import make_user_data  # noqa: E402

STATE = ROOT / ".local/resources.json"
TAGS = {"course":"yuntech-115-1", "week":"w03", "group":"g08", "owner":"m2"}


def save(data):
    STATE.parent.mkdir(mode=0o700, exist_ok=True)
    lab.atomic_write(STATE, json.dumps(data, indent=2) + "\n")


def tag_spec(kind):
    tags = [{"Key":k, "Value":v} for k, v in TAGS.items()]
    return json.dumps([{"ResourceType":kind, "Tags":tags}])


def require_tags(ctx, resource_id, kind):
    if kind == "instance":
        value = lab.run_aws(["ec2","describe-instances","--instance-ids",resource_id,
            "--query","Reservations[0].Instances[0].Tags"], ctx["region"])
    elif kind == "security-group":
        value = lab.run_aws(["ec2","describe-security-groups","--group-ids",resource_id,
            "--query","SecurityGroups[0].Tags"], ctx["region"])
    else:
        value = lab.run_aws(["ec2","describe-key-pairs","--key-pair-ids",resource_id,
            "--query","KeyPairs[0].Tags"], ctx["region"])
    actual = {item["Key"]: item["Value"] for item in value}
    if any(actual.get(k) != v for k, v in TAGS.items()):
        raise lab.LabError(f"Ownership tags mismatch for {resource_id}; refusing change.")


def up(args):
    ctx = lab.verify()
    if STATE.exists():
        raise lab.LabError(".local/resources.json already exists; inspect/recover it before creating anything.")
    commit = subprocess.check_output(["git","rev-parse","--verify","HEAD^{commit}"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git","status","--porcelain","--","app/service.py","deploy"], cwd=ROOT, text=True).strip():
        raise lab.LabError("Deployment files have uncommitted changes; commit first.")
    sha, user_data = make_user_data.build(commit)
    plan = (f"CREATE: SG in {args.vpc}; key pair; one t3.micro in {args.subnet} using {args.ami}; "
            f"encrypted gp3 root; IMDSv2 required; TCP 22/80 from {args.source}; commit {sha}")
    lab.approve(plan + "\nCost: EC2 runtime + public IPv4 + EBS. Recovery: deploy prior commit or run down.sh by recorded IDs.", "CREATE")
    data = {"region":ctx["region"], "commit":sha, "tags":TAGS, "vpc_id":args.vpc,
            "subnet_id":args.subnet, "ami_id":args.ami, "source_cidr":args.source}
    sg = lab.run_aws(["ec2","create-security-group","--group-name",f"yuntech-w03-g08-m2-{int(time.time())}",
        "--description","Yuntech W03 g08 m2","--vpc-id",args.vpc,
        "--tag-specifications",tag_spec("security-group")], ctx["region"])
    data["security_group_id"] = sg["GroupId"]; save(data)
    lab.run_aws(["ec2","authorize-security-group-ingress","--group-id",sg["GroupId"],
        "--ip-permissions",json.dumps([{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":args.source}]},
                                      {"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":args.source}]}])], ctx["region"])
    key = ROOT / ".local/w03-g08-m2-ed25519"
    if not key.exists():
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(key)], check=True)
        key.chmod(0o600)
    key_name = f"yuntech-w03-g08-m2-{int(time.time())}"
    kp = lab.run_aws(["ec2","import-key-pair","--key-name",key_name,"--public-key-material",f"fileb://{key}.pub",
        "--tag-specifications",tag_spec("key-pair")], ctx["region"])
    data.update(key_pair_id=kp["KeyPairId"], key_name=key_name, private_key=str(key)); save(data)
    run = lab.run_aws(["ec2","run-instances","--image-id",args.ami,"--instance-type","t3.micro","--subnet-id",args.subnet,
        "--security-group-ids",sg["GroupId"],"--key-name",key_name,"--user-data",user_data.decode(),
        "--metadata-options","HttpTokens=required,HttpEndpoint=enabled",
        "--block-device-mappings",json.dumps([{"DeviceName":"/dev/xvda","Ebs":{"VolumeType":"gp3","Encrypted":True,"DeleteOnTermination":True}}]),
        "--tag-specifications",tag_spec("instance"),"--count","1","--query","Instances[0].InstanceId"], ctx["region"])
    instance_id = run if isinstance(run, str) else run[0]
    data["instance_id"] = instance_id; save(data)
    lab.run_aws(["ec2","wait","instance-running","--instance-ids",instance_id], ctx["region"])
    info = lab.run_aws(["ec2","describe-instances","--instance-ids",instance_id,
        "--query","Reservations[0].Instances[0].{IP:PublicIpAddress,ENI:NetworkInterfaces[0].NetworkInterfaceId,Volume:BlockDeviceMappings[0].Ebs.VolumeId}"], ctx["region"])
    data.update(public_ip=info["IP"], eni_id=info["ENI"], volume_id=info["Volume"]); save(data)
    print(json.dumps({k:data[k] for k in ("instance_id","security_group_id","key_pair_id","volume_id","eni_id","public_ip","commit")}, indent=2))
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"http://{info['IP']}/health", timeout=5) as response:
                body = json.load(response)
            if response.status == 200 and body.get("version") == sha:
                print(json.dumps(body)); return
        except OSError: pass
        time.sleep(5)
    raise lab.LabError("Instance exists but /health was not ready; inspect recorded IDs, do not create another.")


def down(stop):
    ctx = lab.verify()
    data = json.loads(STATE.read_text())
    iid = data["instance_id"]
    require_tags(ctx, iid, "instance")
    action = "STOP" if stop else "DELETE"
    lab.approve(f"{action}: instance {iid}" + (" only" if stop else f", SG {data['security_group_id']}, key pair {data['key_pair_id']}; EBS/ENI follow instance"), action)
    if stop:
        lab.run_aws(["ec2","stop-instances","--instance-ids",iid],ctx["region"])
        lab.run_aws(["ec2","wait","instance-stopped","--instance-ids",iid],ctx["region"]); print("stopped", iid); return
    require_tags(ctx, data["security_group_id"], "security-group")
    require_tags(ctx, data["key_pair_id"], "key-pair")
    lab.run_aws(["ec2","terminate-instances","--instance-ids",iid],ctx["region"])
    lab.run_aws(["ec2","wait","instance-terminated","--instance-ids",iid],ctx["region"])
    for _ in range(30):
        try:
            lab.run_aws(["ec2","delete-security-group","--group-id",data["security_group_id"]],ctx["region"]); break
        except lab.LabError: time.sleep(3)
    lab.run_aws(["ec2","delete-key-pair","--key-pair-id",data["key_pair_id"]],ctx["region"])
    print("terminated and deleted recorded resources")


def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    u=sub.add_parser("up"); u.add_argument("--vpc",required=True); u.add_argument("--subnet",required=True); u.add_argument("--ami",required=True); u.add_argument("--source",required=True)
    d=sub.add_parser("down"); d.add_argument("--stop",action="store_true")
    a=p.parse_args()
    try: up(a) if a.cmd=="up" else down(a.stop)
    except (lab.LabError, OSError, subprocess.SubprocessError, KeyError, ValueError) as exc:
        print("STOP: "+str(exc),file=sys.stderr); return 1
    return 0
if __name__ == "__main__": sys.exit(main())
