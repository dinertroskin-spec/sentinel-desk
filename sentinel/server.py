"""Loopback-only HTTP adapter with no third-party assets or CORS."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import urlsplit

from .demo import demo_text
from .rules import RULES

MAX_BODY = 2 * 1024 * 1024
STATIC = Path(__file__).with_name("static")


def make_server(store, port=8765):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, status, body, content_type="application/json; charset=utf-8", attachment=None):
            payload = body.encode("utf-8") if isinstance(body, str) else json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if attachment:
                self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
            self.end_headers()
            self.wfile.write(payload)

        def valid_host(self):
            return self.headers.get("Host") in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}

        def do_GET(self):
            if not self.valid_host():
                return self.send(403, {"error": "invalid Host"})
            path = urlsplit(self.path).path
            if path == "/api/state":
                return self.send(200, store.snapshot())
            if path == "/api/rules":
                return self.send(200, RULES)
            if path == "/api/health":
                return self.send(200, {"status": "ok"})
            if path == "/api/export":
                return self.send(200, store.report(), "text/markdown; charset=utf-8", "sentinel-report.md")
            if path.startswith("/api/incidents/"):
                try:
                    return self.send(200, store.detail(path.rsplit("/", 1)[1]))
                except KeyError:
                    return self.send(404, {"error": "incident not found"})
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8"),
                      "/favicon.svg": ("favicon.svg", "image/svg+xml")}
            if path in assets:
                name, mime = assets[path]
                return self.send(200, (STATIC / name).read_text(encoding="utf-8"), mime)
            return self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.valid_host():
                return self.send(403, {"error": "invalid Host"})
            origin = self.headers.get("Origin")
            if self.headers.get("X-Sentinel-Request") != "1" or (origin and origin != f'http://{self.headers.get("Host")}'):
                return self.send(403, {"error": "same-origin request required"})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.send(415, {"error": "application/json required"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size <= 0 or size > MAX_BODY:
                    return self.send(413, {"error": "request must be between 1 byte and 2 MiB"})
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise ValueError("JSON object required")
                path = urlsplit(self.path).path
                if path == "/api/demo":
                    return self.send(200, store.ingest(demo_text(), "jsonl", "demo"))
                if path == "/api/import":
                    text, source, fmt = data.get("text"), data.get("source"), data.get("format")
                    if not isinstance(text, str) or not isinstance(source, str) or not 1 <= len(source.strip()) <= 100:
                        raise ValueError("text and source (1-100 characters) are required")
                    return self.send(200, store.ingest(text, fmt, source.strip()))
                if path.startswith("/api/incidents/"):
                    return self.send(200, store.update(path.rsplit("/", 1)[1], data.get("status"), data.get("note")))
                return self.send(404, {"error": "not found"})
            except KeyError:
                return self.send(404, {"error": "incident not found"})
            except (ValueError, TypeError, UnicodeDecodeError) as exc:
                return self.send(400, {"error": str(exc)[:200]})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server
