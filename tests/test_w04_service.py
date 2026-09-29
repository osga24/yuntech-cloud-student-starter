"""Offline W4 public-contract tests. These make no AWS calls."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
spec = importlib.util.spec_from_file_location("w04_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class ServiceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reporter, cls.operator = "reporter-test-token", "operator-test-token"
        cls.env = patch.dict(os.environ, REPORTER_TOKEN=cls.reporter, OPERATOR_TOKEN=cls.operator)
        cls.env.start()
        cls.temp = tempfile.TemporaryDirectory()
        version = Path(cls.temp.name) / "version"
        version.write_text("b" * 40)
        cls.server = service.make_server(version, port=0)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.worker.join(timeout=2)
        cls.temp.cleanup(); cls.env.stop()

    def request(self, method, path, token=None, body=None):
        headers = {}
        if token: headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)
        with response:
            return response.status, json.load(response)

    def fixture(self, name):
        return json.loads((FIXTURES / name).read_text())

    def test_health_and_display_page(self):
        status, body = self.request("GET", "/health")
        self.assertEqual((status, body["auth_configured"]), (200, True))
        with urllib.request.urlopen(self.base + "/") as response:
            page = response.read().decode()
        self.assertIn("textContent", page)
        self.assertNotIn("innerHTML", page)
        self.assertNotIn("localStorage", page)

    def test_fixture_contract_and_auth_order(self):
        valid = self.fixture("valid_event.json")
        invalid_time = self.fixture("invalid_timezone.json")
        invalid_extra = self.fixture("invalid_extra_field.json")
        status, _ = self.request("POST", "/events", body=invalid_time)
        self.assertEqual(status, 401)  # Auth happens before validation.
        self.assertEqual(self.request("POST", "/events", self.operator, valid)[0], 403)
        status, body = self.request("POST", "/events", self.reporter, invalid_time)
        self.assertEqual((status, body["field"]), (400, "observed_at"))
        status, body = self.request("POST", "/events", self.reporter, invalid_extra)
        self.assertEqual((status, body["field"]), (400, "student_name"))

    def test_create_duplicate_list_and_detail(self):
        event = self.fixture("valid_event.json")
        status, created = self.request("POST", "/events", self.reporter, event)
        self.assertEqual(status, 201)
        self.assertEqual(created["event_id"], event["event_id"])
        self.assertTrue(created["received_at"].endswith("Z"))
        self.assertEqual(self.request("POST", "/events", self.reporter, event)[0], 409)
        self.assertEqual(self.request("GET", "/events", self.reporter)[0], 403)
        status, listing = self.request("GET", "/events", self.operator)
        self.assertEqual(status, 200)
        self.assertIn(event["event_id"], [item["event_id"] for item in listing])
        status, detail = self.request("GET", "/events/" + event["event_id"], self.operator)
        self.assertEqual((status, detail["event_id"]), (200, event["event_id"]))


if __name__ == "__main__":
    unittest.main()
