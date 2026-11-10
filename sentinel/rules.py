"""Deterministic, event-time rules. One investigation per rule and actor."""
from collections import defaultdict, deque
from datetime import datetime
import hashlib

RULES = [
    {"id": "SSH-001", "name": "SSH brute force", "severity": "high", "window": 300,
     "threshold": 5, "description": "5 неудачных SSH-входов с одного IP за 5 минут.",
     "response": "Проверьте владельца IP, журнал SSH и допустимость попыток входа. При подтверждении ограничьте доступ и проверьте учётные записи."},
    {"id": "SSH-002", "name": "Password spraying", "severity": "high", "window": 600,
     "threshold": 5, "description": "Неудачные SSH-входы в 5 разных учётных записей с одного IP за 10 минут.",
     "response": "Проверьте список затронутых пользователей, применение MFA и наличие успешных входов с этого IP."},
    {"id": "SSH-003", "name": "Success after failures", "severity": "critical", "window": 600,
     "threshold": 5, "description": "Успешный SSH-вход после 5 неудачных с теми же IP и пользователем за 10 минут.",
     "response": "Подтвердите вход с владельцем учётной записи. Изучите последующие действия; при компрометации отзовите доступ и смените секреты."},
    {"id": "WEB-001", "name": "Web path discovery", "severity": "medium", "window": 120,
     "threshold": 8, "description": "Ответы 404 на 8 разных путей с одного IP за 2 минуты.",
     "response": "Изучите пути и User-Agent в исходных логах. Исключите легитимный сканер или неисправный клиент."},
    {"id": "OPS-001", "name": "HTTP error burst", "severity": "high", "window": 60,
     "threshold": 5, "description": "5 HTTP-ответов 5xx у одного сервиса за 1 минуту.",
     "response": "Сопоставьте ошибки с релизами, метриками и зависимостями сервиса. Зафиксируйте влияние на пользователей."},
]


def seconds(event):
    return datetime.fromisoformat(event["timestamp"]).timestamp()


def detect(events: list[dict]) -> list[dict]:
    ordered = sorted(events, key=lambda e: (e["timestamp"], e["id"]))
    findings = []
    for rule in RULES:
        groups = defaultdict(list)
        for e in ordered:
            rid = rule["id"]
            if rid.startswith("SSH") and e["kind"] == "auth_failure":
                actor = f'{e["ip"]} / {e["user"]} @ {e["source"]}' if rid == "SSH-003" else f'{e["ip"]} @ {e["source"]}'
                groups[actor].append(e)
            elif rid == "SSH-003" and e["kind"] == "auth_success":
                groups[f'{e["ip"]} / {e["user"]} @ {e["source"]}'].append(e)
            elif rid == "WEB-001" and e["kind"] == "http" and e["status"] == 404:
                groups[f'{e["ip"]} @ {e["source"]} / {e["service"]}'].append(e)
            elif rid == "OPS-001" and e["kind"] == "http" and e["status"] >= 500:
                groups[e["service"]].append(e)
        for actor, group in groups.items():
            window = deque()
            evidence = {}
            for event in group:
                now = seconds(event)
                while window and now - seconds(window[0]) > rule["window"]:
                    window.popleft()
                if rule["id"] == "SSH-003":
                    if event["kind"] == "auth_success":
                        if len(window) >= rule["threshold"]:
                            evidence.update((e["id"], e) for e in [*window, event])
                        window.clear()
                    else:
                        window.append(event)
                    continue
                window.append(event)
                if rule["id"] == "SSH-002":
                    count = len({e["user"] for e in window})
                elif rule["id"] == "WEB-001":
                    count = len({e["path"].split("?", 1)[0] for e in window})
                else:
                    count = len(window)
                if count >= rule["threshold"]:
                    evidence.update((e["id"], e) for e in window)
            if evidence:
                hits = sorted(evidence.values(), key=lambda e: (e["timestamp"], e["id"]))
                findings.append({"id": hashlib.sha256(f'{rule["id"]}:{actor}'.encode()).hexdigest()[:20],
                                 "rule_id": rule["id"], "title": rule["name"],
                                 "severity": rule["severity"], "actor": actor,
                                 "first_seen": hits[0]["timestamp"], "last_seen": hits[-1]["timestamp"],
                                 "event_count": len(hits), "evidence": [e["id"] for e in hits]})
    return findings
