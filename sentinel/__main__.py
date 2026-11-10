import argparse
import json
from pathlib import Path

from .demo import demo_text
from .parser import FORMATS
from .server import make_server
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="Sentinel Desk - local SOC workbench")
    parser.add_argument("--db", default="data/sentinel.sqlite3", help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Start the dashboard on loopback")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--demo", action="store_true", help="Load synthetic events before starting")
    ingest = sub.add_parser("ingest", help="Import a UTF-8 log file")
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--format", choices=FORMATS, required=True)
    ingest.add_argument("--source", required=True)
    sub.add_parser("demo", help="Load synthetic events")
    export = sub.add_parser("export", help="Export a Markdown incident report")
    export.add_argument("--output", type=Path, default=Path("report.md"))
    args = parser.parse_args()
    store = Store(args.db)
    if args.command == "serve":
        if args.demo:
            store.ingest(demo_text(), "jsonl", "demo")
        server = make_server(store, args.port)
        print(f"Sentinel Desk: http://127.0.0.1:{server.server_port} (Ctrl+C to stop)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    elif args.command == "ingest":
        if not 1 <= len(args.source.strip()) <= 100:
            parser.error("source must contain 1-100 characters")
        result = store.ingest(args.file.read_text(encoding="utf-8-sig"), args.format, args.source.strip())
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "demo":
        print(json.dumps(store.ingest(demo_text(), "jsonl", "demo"), indent=2))
    elif args.command == "export":
        args.output.write_text(store.report(), encoding="utf-8")
        print(f"Report saved: {args.output.resolve()}")


if __name__ == "__main__":
    main()
