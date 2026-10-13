"""Shared local-only MQTT identity loading for W6 tools."""
from pathlib import Path
import ssl

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[1]
IOT = ROOT / ".local" / "iot"
def load_identity(which, code):
    suffix = "gw" if which == "gw" else "consumer"
    endpoint = (IOT / "endpoint").read_text(encoding="utf-8").strip()
    client_id = f"{which}-{code}"
    tls = ssl.create_default_context(cafile=str(IOT / "AmazonRootCA1.pem"))
    tls.load_cert_chain(str(IOT / f"{suffix}.cert.pem"), str(IOT / f"{suffix}.private.key"))
    return endpoint, client_id, tls


def mqtt5_client(client_id, tls):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                         protocol=mqtt.MQTTv5)
    client.tls_set_context(tls)
    return client
