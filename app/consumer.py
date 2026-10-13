#!/usr/bin/env python3
"""Forward approved IoT Core messages to the local inspection API."""
import json
import os
import re
import ssl
import urllib.error
import urllib.request

import paho.mqtt.client as mqtt


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing configuration: {name}")
    return value


def main():
    endpoint = required("IOT_ENDPOINT")
    topic = required("IOT_TOPIC")
    client_id = required("IOT_CLIENT_ID")
    allowed = {item.strip() for item in required("IOT_DEVICE_IDS").split(",") if item.strip()}
    ca, cert, key = (required(k) for k in ("IOT_CA", "IOT_CERT", "IOT_KEY"))
    token = required("REPORTER_TOKEN")

    tls = ssl.create_default_context(cafile=ca)
    tls.load_cert_chain(certfile=cert, keyfile=key)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                         protocol=mqtt.MQTTv5)
    client.tls_set_context(tls)

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            print(f"connect_failed rc={reason_code.value}", flush=True)
            return
        result, _ = client.subscribe(topic, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            print(f"subscribe_failed rc={result}", flush=True)

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        code = getattr(reason_codes[0], "value", 255) if reason_codes else 255
        print(f"subscribed rc={code}", flush=True)

    def on_message(client, userdata, message):
        event_id = "<invalid>"
        result = "rejected"
        try:
            event = json.loads(message.payload)
            if not isinstance(event, dict):
                raise ValueError("payload must be an object")
            candidate = event.get("event_id")
            if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", candidate):
                event_id = candidate
            device_id = event.get("device_id")
            if not isinstance(device_id, str) or device_id not in allowed:
                result = "rejected"
            else:
                request = urllib.request.Request(
                    "http://127.0.0.1:8080/events",
                    data=json.dumps(event, separators=(",", ":")).encode(),
                    headers={"Authorization": f"Bearer {token}",
                             "Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(request, timeout=8) as response:
                        status = response.status
                    result = "created" if status == 201 else "duplicate" if status == 200 else "rejected"
                except urllib.error.HTTPError as exc:
                    result = "rejected" if 400 <= exc.code < 500 else "error"
                except (urllib.error.URLError, TimeoutError, OSError):
                    result = "error"
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
            result = "rejected"
        print(f"event_id={event_id} result={result}", flush=True)

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.connect(endpoint, 8883, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()
