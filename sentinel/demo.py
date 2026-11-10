"""Synthetic, deterministic fixtures. All IPs use documentation address ranges."""
from datetime import datetime, timedelta, timezone
import json


def demo_text():
    base = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
    records = []
    def add(offset, kind="http", ip="192.0.2.10", **extra):
        records.append({"timestamp": (base + timedelta(seconds=offset)).isoformat(),
                        "kind": kind, "ip": ip, **extra})
    for n in range(65):
        add(n * 13, status=200, path=["/", "/api/health", "/api/orders"][n % 3], method="GET", service="checkout-api")
    for n in range(7):
        add(60 + n * 18, "auth_failure", "203.0.113.42", user="deploy", service="sshd")
    add(195, "auth_success", "203.0.113.42", user="deploy", service="sshd")
    for n, user in enumerate(["admin", "root", "backup", "postgres", "ubuntu", "support"]):
        add(250 + n * 20, "auth_failure", "198.51.100.23", user=user, service="sshd")
    for n, path in enumerate(["/.env", "/wp-admin", "/.git/config", "/admin", "/backup.zip", "/config", "/actuator", "/phpinfo.php", "/debug", "/server-status"]):
        add(420 + n * 8, ip="203.0.113.77", status=404, path=path, method="GET", service="checkout-api")
    for n in range(9):
        add(620 + n * 5, status=502, path="/api/payments", method="POST", service="checkout-api")
    return "\n".join(json.dumps(r) for r in records)
