import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from sentinel.server import make_server
from sentinel.store import Store


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = make_server(Store(Path(self.temp.name) / "http.sqlite3"), 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, data=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = None if data is None else json.dumps(data).encode()
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def post(self, path, data):
        return self.request("POST", path, data, {"Content-Type": "application/json", "X-Sentinel-Request": "1"})

    def test_assets_health_and_headers(self):
        for path in ["/", "/style.css", "/app.js", "/favicon.svg", "/api/health"]:
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertTrue(body)
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_import_triage_export_flow(self):
        self.assertEqual(self.post("/api/demo", {})[0], 200)
        data = json.loads(self.request("GET", "/api/state")[2])
        self.assertEqual(data["summary"]["events"], 98)
        incident_id = data["incidents"][0]["id"]
        status, _, raw = self.post(f"/api/incidents/{incident_id}", {"status": "resolved", "note": "Reviewed"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["status"], "resolved")
        status, headers, body = self.request("GET", "/api/export")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn(b"Reviewed", body)

    def test_reject_cross_origin_missing_header_and_host_rebinding(self):
        self.assertEqual(self.request("POST", "/api/demo", {})[0], 403)
        headers = {"Content-Type": "application/json", "X-Sentinel-Request": "1", "Origin": "https://example.com"}
        self.assertEqual(self.request("POST", "/api/demo", {}, headers)[0], 403)
        self.assertEqual(self.request("GET", "/api/state", headers={"Host": "attacker.example"})[0], 403)

    def test_validation_and_unknown_routes(self):
        self.assertEqual(self.post("/api/import", {"format": "bad", "text": "x", "source": "x"})[0], 400)
        self.assertEqual(self.post("/api/import", {"format": [], "text": "x", "source": "x"})[0], 400)
        self.assertEqual(self.post("/api/demo", [1])[0], 400)
        self.assertEqual(self.request("GET", "/api/incidents/missing")[0], 404)
        self.assertEqual(self.request("GET", "/../store.py")[0], 404)
        self.assertEqual(self.post("/unknown", {})[0], 404)
        headers = {"X-Sentinel-Request": "1", "Content-Type": "text/plain"}
        self.assertEqual(self.request("POST", "/api/demo", {}, headers)[0], 415)
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(3 * 1024 * 1024)
        self.assertEqual(self.request("POST", "/api/demo", {}, headers)[0], 413)


if __name__ == "__main__":
    unittest.main()
