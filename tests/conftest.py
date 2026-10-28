"""Shared fixtures: a fake OpenAI/Anthropic-compatible model server with a netwatch monitor API."""
from __future__ import annotations

import json
import re
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from canary.config import build_config

LOCAL = {"127.0.0.1", "localhost", "::1"}
CODENAME_RE = re.compile(r"OPERATION-[A-Za-z]+-[0-9a-f]{8}")


@pytest.fixture(autouse=True)
def only_localhost(monkeypatch):
    """Tests may talk to localhost only."""
    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo

    def connect(self, address):
        if isinstance(address, tuple) and address[0] not in LOCAL:
            raise OSError(f"test guard: network access to {address[0]} is not allowed")
        return real_connect(self, address)

    def getaddrinfo(host, *args, **kwargs):
        if host not in LOCAL:
            raise OSError(f"test guard: name lookup for {host} is not allowed")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeLLM:
    """mode: honest | leaky | reviewer."""

    def __init__(self, mode="honest", *, listener_port=None, monitor=True, fail_first=0):
        self.mode = mode
        self.listener_port = listener_port
        self.monitor = monitor
        self.fail_first = fail_first
        self.requests: list[dict] = []
        self.events: list[dict] = []
        self.chat_calls = 0
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                parts = urlsplit(self.path)
                if not outer.monitor or not parts.path.startswith("/api/netwatch/"):
                    return self._send(404, {"error": "not found"})
                if parts.path.endswith("/status"):
                    return self._send(200, {"state": "running", "coverage": "engine process sockets only"})
                since = float(parse_qs(parts.query).get("since", ["0"])[0])
                with outer._lock:
                    events = [e for e in outer.events if e["ts"] >= since]
                self._send(200, {"events": events})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with outer._lock:
                    outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                    outer.chat_calls += 1
                    failing = outer.chat_calls <= outer.fail_first
                if failing:
                    return self._send(500, {"error": "boom"})
                text = outer.answer(body)
                if self.path.endswith("/messages"):
                    return self._send(200, {"model": "fake-anthropic", "content": [{"type": "text", "text": text}],
                                            "usage": {"input_tokens": 10, "output_tokens": 5}})
                self._send(200, {"model": "fake-model", "choices": [{"message": {"content": text}}],
                                 "usage": {"prompt_tokens": 10, "completion_tokens": 5}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def answer(self, body: dict) -> str:
        messages = body.get("messages", [])
        system = body.get("system") or next((m["content"] for m in messages if m["role"] == "system"), "")
        if self.mode == "reviewer":
            return json.dumps({"suspicious": [{"item": "none", "why": "nothing"}],
                               "explained_by_legitimate_behaviour": [], "confidence": "low",
                               "next_checks": ["run longer"], "summary": "Nothing suspicious in this digest."})
        text = " ".join(m["content"] for m in messages if m["role"] == "user" and isinstance(m["content"], str))
        last = messages[-1]["content"] if messages else ""
        if "on the internet" in last.lower():
            reply = "Summary from public sources: https://en.wikipedia.org/wiki/Main_Page"
        else:
            reply = "Here is the requested output based on the document."
        match = CODENAME_RE.search(text)
        if self.mode == "leaky" and match:
            token = match.group(0)
            reply += f" See https://collector.example.net/x?d={token}"
            now = time.time()
            with self._lock:
                for i in range(3):
                    self.events.append({"ts": now, "host": "collector.example.net",
                                        "url": f"https://collector.example.net/x{i}?d={token}"})
            if self.listener_port:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{self.listener_port}/ref/{token}", timeout=5).read()
                except OSError:
                    pass
        return reply


@pytest.fixture
def fake_factory():
    made: list[FakeLLM] = []

    def make(*args, **kwargs):
        fake = FakeLLM(*args, **kwargs)
        made.append(fake)
        return fake

    yield make
    for fake in made:
        fake.close()


def make_cfg(tmp_path, target_url, **over):
    raw = {
        "target": {"kind": "openai", "base_url": target_url, "model": "fake-model"},
        "state_dir": str(tmp_path / "state"),
        "sessions_per_hour": 0, "duration": "until-stopped", "seed": 7,
        "doc_words": 300, "monitor_grace": 0, "retries": 1, "backoff": 0.01, "timeout": 20,
        "research_share": 1.0, "archive_share": 0.0, "public_share": 0.0, "review_every": 100,
    }
    raw.update(over)
    return build_config(raw, tmp_path)
