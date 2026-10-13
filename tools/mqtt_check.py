#!/usr/bin/env python3
"""Check a W6 gateway or consumer IoT Core identity."""
import argparse
import json
import threading

import paho.mqtt.client as mqtt

from iot_common import load_identity, mqtt5_client


def reason_value(reason):
    return getattr(reason, "value", int(reason) if isinstance(reason, int) else 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True, help="team-member code, e.g. g08-m2")
    parser.add_argument("--as", dest="identity", required=True, choices=("gw", "consumer"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pub")
    group.add_argument("--sub")
    parser.add_argument("--wait", type=int, default=5)
    args = parser.parse_args()
    if args.wait < 1 or args.wait > 300:
        parser.error("--wait must be between 1 and 300 seconds")

    endpoint, client_id, tls = load_identity(args.identity, args.code)
    client = mqtt5_client(client_id, tls)
    connected = threading.Event()
    completed = threading.Event()
    state = {"connack": 255, "acks": {}}

    def on_connect(client, userdata, flags, reason_code, properties):
        value = reason_value(reason_code)
        state["connack"] = value
        print(f"connack={value}", flush=True)
        connected.set()
        if value != 0:
            completed.set()
        elif args.sub:
            result, _ = client.subscribe(args.sub, qos=1)
            if result != mqtt.MQTT_ERR_SUCCESS:
                print(f"suback={result}", flush=True)
                completed.set()
        else:
            payload = json.dumps({"check": "t2", "code": args.code}, separators=(",", ":"))
            info = client.publish(args.pub, payload=payload, qos=1)
            state["mid"] = info.mid
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                print(f"puback={info.rc}", flush=True)
                completed.set()
            elif info.mid in state["acks"]:
                print(f"puback={state['acks'][info.mid]}", flush=True)
                completed.set()

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        value = reason_value(reason_codes[0]) if reason_codes else 255
        print(f"suback={value}", flush=True)
        if value >= 128:
            completed.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        value = reason_value(reason_code)
        state["acks"][mid] = value
        if mid == state.get("mid"):
            print(f"puback={value}", flush=True)
            completed.set()

    def on_message(client, userdata, message):
        print(f"recv topic={message.topic} payload={message.payload.decode('utf-8', errors='replace')}", flush=True)
        completed.set()

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_publish = on_publish
    client.on_message = on_message
    client.connect(endpoint, 8883, keepalive=60)
    client.loop_start()
    try:
        if not connected.wait(args.wait):
            raise SystemExit("STOP: MQTT CONNACK timeout")
        if args.pub:
            if not completed.wait(args.wait):
                raise SystemExit("STOP: MQTT PUBACK timeout")
        elif state["connack"] == 0:
            if not completed.wait(args.wait):
                print("STOP: no subscribed message received", flush=True)
    finally:
        client.disconnect()
        client.loop_stop()


if __name__ == "__main__":
    main()
