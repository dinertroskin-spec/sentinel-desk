"""Normalize a deliberately small set of log formats. No inference of log years."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

SSH = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<action>Failed password|Accepted password|Accepted publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
NGINX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) \S+(?: .*)?$'
)
FORMATS = ("ssh", "nginx", "jsonl")


def timestamp(value: str) -> str:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def normalize(record: dict, source: str) -> dict:
    event = {"timestamp": timestamp(record["timestamp"]), "kind": record["kind"],
             "source": source, "ip": str(ipaddress.ip_address(record["ip"])),
             "user": str(record.get("user", ""))[:200],
             "service": str(record.get("service", "web"))[:200],
             "path": str(record.get("path", ""))[:2048],
             "method": str(record.get("method", ""))[:20],
             "status": int(record.get("status", 0))}
    if event["kind"] not in {"auth_failure", "auth_success", "http"}:
        raise ValueError("unsupported event kind")
    if event["kind"] == "http" and not 100 <= event["status"] <= 599:
        raise ValueError("invalid HTTP status")
    if event["kind"].startswith("auth_") and not event["user"]:
        raise ValueError("authentication event requires a user")
    canonical = json.dumps(event, sort_keys=True, ensure_ascii=False)
    event["id"] = hashlib.sha256(canonical.encode()).hexdigest()
    return event


def parse_line(line: str, fmt: str, source: str) -> dict:
    if fmt == "jsonl":
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("JSON line must be an object")
    elif fmt == "ssh":
        match = SSH.match(line)
        if not match:
            raise ValueError("expected ISO 8601 SSH log line (with year and timezone)")
        m = match.groupdict()
        record = {"timestamp": m["ts"], "ip": m["ip"], "user": m["user"],
                  "kind": "auth_failure" if m["action"].startswith("Failed") else "auth_success",
                  "service": "sshd"}
    elif fmt == "nginx":
        match = NGINX.match(line)
        if not match:
            raise ValueError("expected nginx combined/common access log")
        m = match.groupdict()
        record = {"timestamp": datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").isoformat(),
                  "kind": "http", "ip": m["ip"], "status": m["status"],
                  "path": m["path"], "method": m["method"]}
    else:
        raise ValueError("unsupported format")
    return normalize(record, source)


def parse_text(text: str, fmt: str, source: str) -> tuple[list[dict], list[dict]]:
    if fmt not in FORMATS:
        raise ValueError("unsupported format")
    events, errors = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(parse_line(line, fmt, source))
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            errors.append({"line": number, "reason": str(exc)[:200]})
    return events, errors
