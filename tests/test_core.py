import json
from pathlib import Path
import tempfile
import unittest

from sentinel.demo import demo_text
from sentinel.parser import normalize, parse_text
from sentinel.rules import detect
from sentinel.store import Store


def auth(second, user="root", ip="203.0.113.1", kind="auth_failure", source="host-a"):
    return normalize({"timestamp": f"2026-01-01T00:{second // 60:02}:{second % 60:02}+00:00",
                      "kind": kind, "ip": ip, "user": user, "service": "sshd"}, source)


class ParserTests(unittest.TestCase):
    def test_ssh_ipv6_and_timezone(self):
        line = "2026-01-01T03:00:00+03:00 host sshd[42]: Failed password for invalid user admin from 2001:db8::1 port 2200 ssh2"
        events, errors = parse_text(line, "ssh", "ssh-a")
        self.assertFalse(errors)
        self.assertEqual(events[0]["timestamp"], "2026-01-01T00:00:00.000000+00:00")
        self.assertEqual(events[0]["ip"], "2001:db8::1")
        self.assertEqual(events[0]["user"], "admin")

    def test_nginx(self):
        events, errors = parse_text('192.0.2.1 - - [20/Oct/2026:09:00:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8"', "nginx", "web")
        self.assertFalse(errors)
        self.assertEqual((events[0]["path"], events[0]["status"]), ("/.env", 404))

    def test_rejections_keep_line_numbers(self):
        events, errors = parse_text('\nnot-json\n[]\n' + demo_text().splitlines()[0], "jsonl", "web")
        self.assertEqual(len(events), 1)
        self.assertEqual([e["line"] for e in errors], [2, 3])

    def test_invalid_values(self):
        base = {"timestamp": "2026-01-01T00:00:00Z", "kind": "http", "ip": "192.0.2.1", "status": 200}
        for field, bad in [("ip", "not-an-ip"), ("timestamp", "2026-01-01T00:00:00"), ("kind", "shell"), ("status", 999)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                normalize(dict(base, **{field: bad}), "test")

    def test_microseconds_do_not_collapse(self):
        a = {"timestamp": "2026-01-01T00:00:00.001Z", "kind": "http", "ip": "192.0.2.1", "status": 200}
        b = dict(a, timestamp="2026-01-01T00:00:00.002Z")
        self.assertNotEqual(normalize(a, "s")["id"], normalize(b, "s")["id"])


class RuleTests(unittest.TestCase):
    def ids(self, events):
        return {r["rule_id"] for r in detect(events)}

    def test_brute_threshold_and_inclusive_window(self):
        events = [auth(t) for t in [0, 60, 120, 180, 300]]
        self.assertNotIn("SSH-001", self.ids(events[:4]))
        self.assertIn("SSH-001", self.ids(events))
        self.assertNotIn("SSH-001", self.ids([auth(t) for t in [0, 60, 120, 180, 301]]))

    def test_spray_counts_distinct_users(self):
        self.assertNotIn("SSH-002", self.ids([auth(t) for t in range(6)]))
        self.assertIn("SSH-002", self.ids([auth(t, user=f"user{t}") for t in range(5)]))

    def test_success_requires_same_user_ip_and_source(self):
        failures = [auth(t) for t in range(5)]
        self.assertIn("SSH-003", self.ids(failures + [auth(10, kind="auth_success")]))
        for change in [{"user": "admin"}, {"ip": "203.0.113.2"}, {"source": "host-b"}]:
            self.assertNotIn("SSH-003", self.ids(failures + [auth(10, kind="auth_success", **change)]))

    def test_success_resets_failure_sequence(self):
        events = [auth(0), auth(1), auth(2), auth(3, kind="auth_success"), auth(4), auth(5), auth(6, kind="auth_success")]
        self.assertNotIn("SSH-003", self.ids(events))

    def test_separate_sources_do_not_merge_ssh_attempts(self):
        self.assertNotIn("SSH-001", self.ids([auth(t, source=f"host-{t % 2}") for t in range(6)]))

    def test_web_query_variants_are_not_distinct_paths(self):
        def web(t, path, status=404, service="api"):
            return normalize({"timestamp": f"2026-01-01T00:00:{t:02}Z", "kind": "http", "ip": "192.0.2.1", "path": path, "status": status, "service": service}, "web")
        self.assertNotIn("WEB-001", self.ids([web(t, f"/missing?q={t}") for t in range(8)]))
        self.assertIn("WEB-001", self.ids([web(t, f"/path-{t}") for t in range(8)]))
        self.assertNotIn("OPS-001", self.ids([web(t, "/", 500, f"service-{t % 2}") for t in range(6)]))
        self.assertIn("OPS-001", self.ids([web(t, "/", 503) for t in range(5)]))

    def test_input_order_does_not_change_findings(self):
        events, _ = parse_text(demo_text(), "jsonl", "demo")
        self.assertEqual(detect(events), detect(list(reversed(events))))
        self.assertEqual(len(detect(events)), 6)
        self.assertEqual(self.ids(events), {"SSH-001", "SSH-002", "SSH-003", "WEB-001", "OPS-001"})


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "state.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_import_is_idempotent(self):
        first = self.store.ingest(demo_text(), "jsonl", "demo")
        second = self.store.ingest(demo_text(), "jsonl", "demo")
        self.assertEqual(first["added"], 98)
        self.assertEqual(second["added"], 0)
        self.assertEqual(second["duplicates"], 98)
        self.assertEqual(self.store.snapshot()["summary"]["incidents"], 6)

    def test_incremental_detection_and_status_preservation(self):
        events = [auth(t) for t in range(6)]
        raw = lambda batch: "\n".join(json.dumps(e) for e in batch)
        self.store.ingest(raw(events[:4]), "jsonl", "host-a")
        self.assertEqual(self.store.snapshot()["summary"]["incidents"], 0)
        self.store.ingest(raw(events[4:5]), "jsonl", "host-a")
        incident_id = self.store.snapshot()["incidents"][0]["id"]
        self.store.update(incident_id, "investigating", "Проверен источник")
        self.store.ingest(raw(events[5:]), "jsonl", "host-a")
        result = self.store.detail(incident_id)
        self.assertEqual(result["status"], "investigating")
        self.assertEqual(result["event_count"], 6)
        self.assertEqual(len(result["history"]), 1)
        reopened = Store(self.store.path)
        self.assertEqual(reopened.detail(incident_id)["history"][0]["note"], "Проверен источник")

    def test_invalid_transition_and_missing_incident(self):
        self.store.ingest(demo_text(), "jsonl", "demo")
        incident_id = self.store.snapshot()["incidents"][0]["id"]
        with self.assertRaises(ValueError):
            self.store.update(incident_id, "deleted", "test")
        with self.assertRaises(ValueError):
            self.store.update(incident_id, "resolved", "  ")
        with self.assertRaises(KeyError):
            self.store.update("missing", "new", "test")
        self.assertEqual(self.store.detail(incident_id)["history"], [])

    def test_partial_import_reports_rejections(self):
        result = self.store.ingest(demo_text() + "\nBAD", "jsonl", "demo")
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["added"], 98)

    def test_report_includes_decision_and_no_html(self):
        self.store.ingest(demo_text(), "jsonl", "demo")
        incident_id = self.store.snapshot()["incidents"][0]["id"]
        self.store.update(incident_id, "resolved", "<script>alert(1)</script>")
        report = self.store.report()
        self.assertIn("[resolved]", report)
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)


if __name__ == "__main__":
    unittest.main()
