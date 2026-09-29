#!/usr/bin/env python3
"""In-memory inspection event service."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac, json, os, re, threading
from pathlib import Path
from urllib.parse import unquote, urlsplit

ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
DEVICE_RE = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
FIELDS = {"event_id", "device_id", "observed_at", "type", "note"}
REQUIRED = {"event_id", "device_id", "observed_at", "type"}
TYPES = {"status", "anomaly", "test"}


def make_server(version_file, port=8080):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    reporter, operator = os.environ.get("REPORTER_TOKEN", ""), os.environ.get("OPERATOR_TOKEN", "")
    configured = bool(reporter and operator and reporter != operator)
    events, by_id, lock = [], {}, threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup(); self.connection.settimeout(5)

        def reply(self, status, body):
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(data)

        def error(self, status, reason, field):
            self.reply(status, {"error": reason, "field": field})

        def authorize(self, expected):
            header = self.headers.get("Authorization", "")
            supplied = header[7:] if header.startswith("Bearer ") else ""
            if not supplied:
                self.error(401, "authentication_required", "authorization"); return False
            known = (reporter, operator) if configured else ()
            if not any(hmac.compare_digest(supplied, item) for item in known):
                self.error(401, "invalid_token", "authorization"); return False
            if not hmac.compare_digest(supplied, expected):
                self.error(403, "forbidden", "authorization"); return False
            return True

        def read_event(self):
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                self.error(400, "content_type_must_be_application_json", "content_type"); return
            try: length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.error(400, "invalid_content_length", "body"); return
            if length < 0 or length > 4096:
                self.error(400, "body_too_large", "body"); return
            try: body = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.error(400, "invalid_json", "body"); return
            if not isinstance(body, dict):
                self.error(400, "must_be_an_object", "body"); return
            extra, missing = sorted(set(body) - FIELDS), sorted(REQUIRED - set(body))
            if extra: self.error(400, "unknown_field", extra[0]); return
            if missing: self.error(400, "required", missing[0]); return
            if not isinstance(body["event_id"], str) or not ID_RE.fullmatch(body["event_id"]):
                self.error(400, "invalid_format", "event_id"); return
            if not isinstance(body["device_id"], str) or not DEVICE_RE.fullmatch(body["device_id"]):
                self.error(400, "invalid_format", "device_id"); return
            if not isinstance(body["type"], str) or body["type"] not in TYPES:
                self.error(400, "invalid_value", "type"); return
            if "note" in body and (not isinstance(body["note"], str) or len(body["note"]) > 200):
                self.error(400, "invalid_value", "note"); return
            if not isinstance(body["observed_at"], str):
                self.error(400, "timezone_required", "observed_at"); return
            try: observed = datetime.fromisoformat(body["observed_at"].replace("Z", "+00:00"))
            except ValueError:
                self.error(400, "invalid_iso8601", "observed_at"); return
            if observed.tzinfo is None or observed.utcoffset() is None:
                self.error(400, "timezone_required", "observed_at"); return
            return body

        def do_POST(self):
            if urlsplit(self.path).path != "/events": self.error(404, "not_found", "path"); return
            if not self.authorize(reporter): return  # 401/403 must precede validation.
            event = self.read_event()
            if event is None: return
            with lock:
                if event["event_id"] in by_id:
                    self.error(409, "duplicate_event_id", "event_id"); return
                stored = dict(event)
                stored["received_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                events.append(stored); by_id[stored["event_id"]] = stored
            self.reply(201, stored)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/health":
                self.reply(200, {"status":"ok", "service":"inspection", "version":version,
                                 "started_at":started, "auth_configured":configured}); return
            if path == "/": self.page(); return
            if path == "/events" or path.startswith("/events/"):
                if not self.authorize(operator): return
                with lock:
                    if path == "/events": self.reply(200, list(reversed(events[-50:]))); return
                    item = by_id.get(unquote(path[len("/events/"):]))
                    if item is None: self.error(404, "not_found", "event_id")
                    else: self.reply(200, item)
                return
            self.error(404, "not_found", "path")

        def page(self):
            data = PAGE.encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("X-Frame-Options", "DENY")
            self.end_headers(); self.wfile.write(data)

        def log_message(self, fmt, *args):
            pass  # Never log paths, bodies, headers, query strings, or tokens.

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


PAGE = """<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>巡檢事件</title><style>body{font:16px system-ui;max-width:60rem;margin:2rem auto;padding:0 1rem}form{display:flex;gap:.5rem}input{flex:1;padding:.6rem}li{white-space:pre-wrap;background:#f4f6f7;margin:.6rem 0;padding:.8rem}</style></head><body><h1>巡檢事件</h1><form id="form"><label for="token">Operator 權杖</label><input id="token" type="password" autocomplete="off" required><button>讀取最新 50 筆</button></form><p id="message" role="status"></p><ol id="events"></ol><script>
const form=document.getElementById('form'),token=document.getElementById('token'),message=document.getElementById('message'),list=document.getElementById('events');form.addEventListener('submit',async(event)=>{event.preventDefault();const credential=token.value;token.value='';message.textContent='讀取中…';list.replaceChildren();try{const response=await fetch('/events',{headers:{Authorization:'Bearer '+credential}}),body=await response.json();if(!response.ok)throw new Error(body.error||('HTTP '+response.status));for(const item of body){const row=document.createElement('li');row.textContent=JSON.stringify(item,null,2);list.appendChild(row)}message.textContent=`共 ${body.length} 筆`}catch(error){message.textContent='讀取失敗：'+error.message}});
</script></body></html>"""

if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
