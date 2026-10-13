#!/usr/bin/env python3
"""Publish the W6 32-message IoT reconciliation batch."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import threading

import paho.mqtt.client as mqtt

from iot_common import load_identity, mqtt5_client, ROOT

CODE_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")


def reason_value(reason):
    return reason.value if hasattr(reason, "value") else int(reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True, help="unique run label such as r1")
    args = parser.parse_args()
    if not CODE_RE.fullmatch(args.code) or not CODE_RE.fullmatch(args.run):
        parser.error("--code and --run must match ^[A-Za-z0-9-]{1,40}$")
    prefix = f"{args.code}-{args.run}"
    endpoint, client_id, tls = load_identity("gw", args.code)
    client = mqtt5_client(client_id, tls)
    connected = threading.Event()
    ack_event = threading.Event()
    state = {"connack": 255, "mid": None, "ack_code": 255, "count": 0, "acks": {}}

    def on_connect(client, userdata, flags, reason_code, properties):
        state["connack"] = reason_value(reason_code)
        connected.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        state["acks"][mid] = reason_value(reason_code)
        if mid == state["mid"]:
            state["ack_code"] = state["acks"][mid]
            ack_event.set()

    client.on_connect = on_connect
    client.on_publish = on_publish
    client.connect(endpoint, 8883, keepalive=60)
    client.loop_start()
    try:
        if not connected.wait(30) or state["connack"] != 0:
            raise SystemExit(f"STOP: MQTT CONNACK failed (rc={state['connack']})")
        messages = []
        for number in range(1, 11):
            device_id = f"{args.code}-d{number:02d}"
            for sequence in range(1, 4):
                event = {
                    "event_id": f"{prefix}-d{number:02d}-{sequence:02d}",
                    "device_id": device_id,
                    "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "type": "status",
                }
                messages.append(event)
        messages.append(messages[0].copy())
        messages.append({
            "event_id": f"{prefix}-d99-01",
            "device_id": f"{args.code}-d99",
            "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "type": "status",
        })

        for event in messages:
            ack_event.clear()
            info = client.publish(f"cxe/{args.code}/gw/events",
                                  json.dumps(event, separators=(",", ":")), qos=1)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise SystemExit(f"STOP: MQTT publish failed (rc={info.rc})")
            state["mid"] = info.mid
            if info.mid in state["acks"]:
                state["ack_code"] = state["acks"][info.mid]
            elif not ack_event.wait(20):
                raise SystemExit(f"STOP: PUBACK timeout after {state['count']} messages")
            if state["ack_code"] >= 128:
                raise SystemExit(f"STOP: PUBACK rejected (rc={state['ack_code']})")
            state["count"] += 1

        run_file = ROOT / ".local" / "w06-last-run.json"
        run_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = run_file.with_suffix(".tmp")
        temp.write_text(json.dumps({"prefix": prefix, "puback_ok": state["count"]}, indent=2) + "\n",
                        encoding="utf-8")
        temp.chmod(0o600)
        temp.replace(run_file)
        print(f"prefix={prefix}")
        print(f"puback_ok={state['count']}/32")
    finally:
        client.disconnect()
        client.loop_stop()


if __name__ == "__main__":
    main()
