#!/usr/bin/env python3
"""Create the two narrowly scoped W6 IoT Core identities."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import lab

RESOURCES = ROOT / ".local" / "resources.json"
IOT_DIR = ROOT / ".local" / "iot"
CODE = "g08-m2"
TOPIC = f"cxe/{CODE}/gw/events"


def write_private(path, data):
    if path.exists() or path.is_symlink():
        raise lab.LabError(f"Refusing to overwrite existing local IoT file: {path.name}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, 0o600)


def read_policy(name, region):
    return lab.run_aws(["iot", "get-policy", "--policy-name", name], region)


def ensure_policy(name, statements, region):
    document = {"Version": "2012-10-17", "Statement": statements}
    try:
        current = read_policy(name, region)
    except lab.LabError as exc:
        if "ResourceNotFoundException" not in str(exc):
            raise
        current = None
    if current is None:
        return lab.run_aws(["iot", "create-policy", "--policy-name", name,
                            "--policy-document", json.dumps(document, separators=(",", ":"))], region)
    existing = current.get("policyDocument", {})
    if isinstance(existing, str):
        existing = json.loads(existing)
    if existing != document:
        raise lab.LabError(f"Existing policy {name} differs from the required least-privilege policy; stop for review.")
    return current


def ensure_attached(policy_name, cert_arn, region):
    result = lab.run_aws(["iot", "list-attached-policies", "--target", cert_arn], region)
    names = {item.get("policyName") for item in result.get("policies", [])}
    if policy_name not in names:
        lab.run_aws(["iot", "attach-policy", "--policy-name", policy_name,
                     "--target", cert_arn], region)


def ensure_certificate(role, resource_key, cert_path, key_path, region):
    data = json.loads(RESOURCES.read_text(encoding="utf-8"))
    existing_id = data.get(resource_key)
    if existing_id:
        if not cert_path.is_file() or not key_path.is_file():
            raise lab.LabError(f"Resource {resource_key} already exists but local key files are missing; refusing replacement.")
        return existing_id
    if cert_path.exists() or key_path.exists():
        raise lab.LabError(f"Local {role} certificate files exist without a recorded ID; inspect before retrying.")
    result = lab.run_aws(["iot", "create-keys-and-certificate", "--set-as-active"], region)
    cert_id = result["certificateId"]
    cert_pem = result["certificatePem"].encode()
    private_key = result["keyPair"]["PrivateKey"].encode()
    try:
        write_private(cert_path, cert_pem)
        write_private(key_path, private_key)
        data[resource_key] = cert_id
        temp = RESOURCES.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(RESOURCES)
    except BaseException:
        # Never print or persist certificate response data beyond the protected key files.
        raise
    return cert_id


def main():
    if not RESOURCES.is_file():
        raise lab.LabError("Missing .local/resources.json from the W3/W5 setup.")
    ctx = lab.verify()
    data = json.loads(RESOURCES.read_text(encoding="utf-8"))
    account = ctx["account"]
    region = ctx["region"]
    if region != "us-east-1":
        raise lab.LabError("W6 policy resources are configured for us-east-1; stop and ask the instructor before changing region.")

    IOT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(IOT_DIR, 0o700)
    endpoint_file = IOT_DIR / "endpoint"
    ca_file = IOT_DIR / "AmazonRootCA1.pem"
    if not endpoint_file.exists():
        endpoint = lab.run_aws(["iot", "describe-endpoint", "--endpoint-type", "iot:Data-ATS"], region)["endpointAddress"]
        write_private(endpoint_file, (endpoint + "\n").encode())
    if not ca_file.exists():
        result = subprocess.run(
            ["curl", "--max-time", "20", "-fsS", "https://www.amazontrust.com/repository/AmazonRootCA1.pem"],
            capture_output=True, timeout=22, check=False,
        )
        if result.returncode:
            raise lab.LabError("Could not download Amazon Root CA 1; no AWS resources were changed.")
        ca = result.stdout[:100_000]
        if not ca.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise lab.LabError("Amazon Root CA download did not look like a PEM certificate.")
        write_private(ca_file, ca)

    gw_policy = f"cxe-{CODE}-gw"
    consumer_policy = f"cxe-{CODE}-consumer"
    gw_id = f"gw-{CODE}"
    consumer_id = f"consumer-{CODE}"
    gw_cert_file, gw_key_file = IOT_DIR / "gw.cert.pem", IOT_DIR / "gw.private.key"
    consumer_cert_file, consumer_key_file = IOT_DIR / "consumer.cert.pem", IOT_DIR / "consumer.private.key"

    summary = (
        f"Create or reuse only W6 IoT Core resources in account ending {account[-4:]}, {region}: "
        f"policies {gw_policy} and {consumer_policy}; one active gateway certificate for client {gw_id}; "
        f"one active consumer certificate for client {consumer_id}; attach each policy to its matching certificate. "
        "No EC2 security-group or public-ingress change. IoT Core charges are metered; this lab sends 32 small events "
        "plus a few checks. Existing EC2/RDS usage continues while running. Recovery: detach the two policies, "
        "deactivate/delete only the two certificate IDs recorded under iot_gw_cert_id and iot_consumer_cert_id, "
        "then delete only these two policies; retain W5 resources. Local certificate files remain in .local/iot until removed."
    )
    lab.approve(summary, "CREATE_IOT")

    gateway_statements = [
        {"Effect": "Allow", "Action": "iot:Connect", "Resource": f"arn:aws:iot:{region}:{account}:client/{gw_id}"},
        {"Effect": "Allow", "Action": "iot:Publish", "Resource": f"arn:aws:iot:{region}:{account}:topic/{TOPIC}"},
    ]
    consumer_statements = [
        {"Effect": "Allow", "Action": "iot:Connect", "Resource": f"arn:aws:iot:{region}:{account}:client/{consumer_id}"},
        {"Effect": "Allow", "Action": "iot:Subscribe", "Resource": f"arn:aws:iot:{region}:{account}:topicfilter/{TOPIC}"},
        {"Effect": "Allow", "Action": "iot:Receive", "Resource": f"arn:aws:iot:{region}:{account}:topic/{TOPIC}"},
    ]
    ensure_policy(gw_policy, gateway_statements, region)
    ensure_policy(consumer_policy, consumer_statements, region)
    gw_cert = ensure_certificate("gateway", "iot_gw_cert_id", gw_cert_file, gw_key_file, region)
    consumer_cert = ensure_certificate("consumer", "iot_consumer_cert_id", consumer_cert_file, consumer_key_file, region)
    for policy_name, cert_id in ((gw_policy, gw_cert), (consumer_policy, consumer_cert)):
        cert_arn = f"arn:aws:iot:{region}:{account}:cert/{cert_id}"
        ensure_attached(policy_name, cert_arn, region)

    data = json.loads(RESOURCES.read_text(encoding="utf-8"))
    data.update(iot_gw_policy=gw_policy, iot_consumer_policy=consumer_policy)
    temp = RESOURCES.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(RESOURCES)
    statuses = {}
    for label, cert_id in (("gateway", gw_cert), ("consumer", consumer_cert)):
        response = lab.run_aws(["iot", "describe-certificate", "--certificate-id", cert_id], region)
        statuses[label] = response["certificateDescription"]["status"]
    if set(statuses.values()) != {"ACTIVE"}:
        raise lab.LabError("One or more W6 certificates are not ACTIVE; inspect IoT Core state before retrying.")
    print(json.dumps({"endpoint": endpoint_file.read_text().strip(), "gateway_certificate": "ACTIVE",
                      "consumer_certificate": "ACTIVE", "policies": [gw_policy, consumer_policy]}, separators=(",", ":")))


if __name__ == "__main__":
    main()
