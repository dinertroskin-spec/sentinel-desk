"""SQLite persistence; imports and rule evaluation commit atomically."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .parser import parse_text
from .rules import detect

STATUSES = ("new", "investigating", "resolved", "false_positive")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, data TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new');
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS imports (
                    id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL,
                    added INTEGER NOT NULL, duplicates INTEGER NOT NULL, rejected INTEGER NOT NULL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, text, fmt, source):
        events, errors = parse_text(text, fmt, source)
        with self.connect() as db:
            # Reserve the write transaction before reading/rebuilding detections.
            db.execute("BEGIN IMMEDIATE")
            before = db.total_changes
            db.executemany("INSERT OR IGNORE INTO events VALUES (?, ?, ?)",
                           [(e["id"], e["timestamp"], json.dumps(e, ensure_ascii=False)) for e in events])
            added = db.total_changes - before
            all_events = [json.loads(r[0]) for r in db.execute("SELECT data FROM events ORDER BY timestamp, id")]
            findings = detect(all_events)
            for finding in findings:
                db.execute("INSERT INTO incidents(id,data) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                           (finding["id"], json.dumps(finding, ensure_ascii=False)))
            db.execute("INSERT INTO imports(timestamp,source,added,duplicates,rejected) VALUES (?,?,?,?,?)",
                       (now(), source, added, len(events) - added, len(errors)))
        return {"added": added, "duplicates": len(events) - added, "rejected": len(errors),
                "errors": errors[:100], "incidents": len(findings)}

    def snapshot(self):
        with self.connect() as db:
            incidents = [dict(json.loads(r["data"]), status=r["status"]) for r in db.execute("SELECT * FROM incidents")]
            events = [json.loads(r[0]) for r in db.execute("SELECT data FROM events ORDER BY timestamp DESC, id LIMIT 200")]
            totals = db.execute("SELECT count(*), min(timestamp), max(timestamp) FROM events").fetchone()
            imports = [dict(r) for r in db.execute("SELECT * FROM imports ORDER BY id DESC LIMIT 10")]
        rank = {"critical": 0, "high": 1, "medium": 2}
        incidents.sort(key=lambda i: (rank[i["severity"]], i["first_seen"], i["id"]))
        return {"incidents": incidents, "events": events, "imports": imports,
                "summary": {"events": totals[0], "incidents": len(incidents),
                            "open": sum(i["status"] in ("new", "investigating") for i in incidents),
                            "critical": sum(i["severity"] == "critical" and i["status"] in ("new", "investigating") for i in incidents),
                            "first_seen": totals[1], "last_seen": totals[2]}}

    def detail(self, incident_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not row:
                raise KeyError(incident_id)
            result = dict(json.loads(row["data"]), status=row["status"])
            # Batch lookups stay below SQLite's conservative parameter limit.
            result["events"] = []
            ids = result["evidence"]
            for offset in range(0, len(ids), 500):
                batch = ids[offset:offset + 500]
                placeholders = ",".join("?" for _ in batch)
                result["events"].extend(json.loads(r[0]) for r in db.execute(
                    f"SELECT data FROM events WHERE id IN ({placeholders})", batch))
            result["events"].sort(key=lambda e: (e["timestamp"], e["id"]))
            result["history"] = [dict(r) for r in db.execute(
                "SELECT timestamp,status,note FROM history WHERE incident_id=? ORDER BY id", (incident_id,))]
        return result

    def update(self, incident_id, status, note):
        if status not in STATUSES:
            raise ValueError("unsupported incident status")
        if not isinstance(note, str) or not note.strip() or len(note) > 2000:
            raise ValueError("note is required (1-2000 characters)")
        with self.connect() as db:
            cursor = db.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
            if not cursor.rowcount:
                raise KeyError(incident_id)
            db.execute("INSERT INTO history(incident_id,timestamp,status,note) VALUES (?,?,?,?)",
                       (incident_id, now(), status, note.strip()))
        return self.detail(incident_id)

    def report(self):
        data = self.snapshot()
        lines = ["# Sentinel Desk - incident report", "", f"Generated (UTC): {now()}",
                 f"Events: {data['summary']['events']} | Open incidents: {data['summary']['open']}", ""]
        def safe(value):
            return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
        for incident in data["incidents"]:
            item = self.detail(incident["id"])
            lines.extend([f"## {item['rule_id']}: {item['title']}", "",
                          f"Actor: {safe(item['actor'])}", f"Severity: {item['severity']} | Status: {item['status']}",
                          f"UTC: {item['first_seen']} - {item['last_seen']}", f"Evidence events: {item['event_count']}", ""])
            for entry in item["history"]:
                lines.append(f"- {entry['timestamp']} [{entry['status']}] {safe(entry['note'])}")
            lines.append("")
        return "\n".join(lines)
