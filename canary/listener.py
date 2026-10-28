"""Optional HTTP listener that logs every request it receives (a canary URL being fetched is evidence)."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .util import append_jsonl, iso

BODY_LIMIT = 4096


class CanaryListener:
    def __init__(self, host: str, port: int, log_path: Path, on_hit=None):
        self.log_path = Path(log_path)
        self.on_hit = on_hit
        self._hits: list[dict] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(length, BODY_LIMIT)).decode("utf-8", errors="replace") if length else ""
                parts = urlsplit(self.path)
                hit = {
                    "ts": time.time(), "time": iso(), "method": self.command, "path": parts.path,
                    "query": parts.query, "host": self.headers.get("Host", ""),
                    "client": self.client_address[0], "ua": self.headers.get("User-Agent", ""),
                    "body": body,
                }
                outer._record(hit)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _handle

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="canary-listener")

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def _record(self, hit: dict) -> None:
        with self._lock:
            self._hits.append(hit)
        append_jsonl(self.log_path, hit)
        if self.on_hit:
            try:
                self.on_hit(hit)
            except Exception:  # a callback bug must not drop the request
                pass

    def hits_between(self, t0: float, t1: float) -> list[dict]:
        with self._lock:
            return [h for h in self._hits if t0 <= h["ts"] <= t1]

    def start(self) -> "CanaryListener":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
