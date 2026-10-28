"""Minimal built-in connection sampler: a monitor for runtimes that have none.

It reads the operating system's connection table at an interval and reports each outbound connection of the watched
processes the first time it is seen. It emits the same event shape as the Basalt Security monitor, so the monitor client
(canary/monitor.py) reads either. It can run inside the test run (network_watch = "builtin") or as a small HTTP server
(python -m canary netwatch) that serves /api/netwatch/status and /api/netwatch/events.

Coverage is limited and said so in the status: a connection that lives for less than the interval can be missed, the
destination is an IP address plus a reverse-DNS name (not the name the program asked for), nothing is captured from
the wire, and encrypted content is not inspected. Without psutil it falls back to netstat (Windows) or ss (Linux),
which can match processes by executable name or PID only.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

log = logging.getLogger("canary.netwatch")

COVERAGE_NOTE = ("Built-in sampler: reads the connection table every interval, so a connection shorter than the interval "
                 "can be missed; hosts are reverse-DNS names of the remote IP, not the names the program asked for; "
                 "no packet capture, no traffic content. It cannot prove that nothing was sent.")
PROXY_PORTS = frozenset({1080, 3128, 7890, 7897, 8118, 9050, 9150, 10808, 10809})
FORGET_AFTER_S = 600.0
MAX_EVENTS = 5000
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# -- parsers for the psutil-free fallbacks (pure functions) --------------------------------------

def _split_endpoint(text: str) -> tuple[str, int]:
    text = text.strip()
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
    else:
        host, _, port = text.rpartition(":")
    host = host.split("%")[0]
    return host, int(port) if port.isdigit() else 0


def parse_netstat_windows(text: str) -> list[dict]:
    """`netstat -ano` lines: Proto Local Foreign State PID."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[-1].isdigit():
            laddr, raddr = _split_endpoint(parts[1]), _split_endpoint(parts[2])
            out.append({"pid": int(parts[-1]), "proto": "tcp", "laddr": laddr, "raddr": raddr, "status": parts[3]})
    return out


def parse_ss(text: str) -> list[dict]:
    """`ss -tnpH` lines: State Recv-Q Send-Q Local Peer users:(("name",pid=1,fd=3))."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        pids = re.findall(r"pid=(\d+)", line)
        for pid in pids or ["0"]:
            out.append({"pid": int(pid), "proto": "tcp", "laddr": _split_endpoint(parts[3]),
                        "raddr": _split_endpoint(parts[4]), "status": parts[0].upper().replace("ESTAB", "ESTABLISHED")})
    return out


def parse_tasklist_csv(text: str) -> dict[int, tuple[str, str]]:
    out = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[1].isdigit():
            out[int(row[1])] = (row[0], "")
    return out


def parse_ps(text: str) -> dict[int, tuple[str, str]]:
    """`ps -eo pid=,comm=,args=`"""
    out = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 2 and parts[0].isdigit():
            out[int(parts[0])] = (parts[1], parts[2] if len(parts) > 2 else "")
    return out


def _run(cmd: list[str]) -> str:
    kwargs = {"creationflags": NO_WINDOW} if os.name == "nt" else {}
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=20, **kwargs)
    return done.stdout


# -- table sources ----------------------------------------------------------------------------

class PsutilSource:
    name = "psutil"

    def __init__(self):
        import psutil
        self.psutil = psutil

    def processes(self) -> dict[int, tuple[str, str]]:
        out = {}
        for proc in self.psutil.process_iter(["pid", "name", "cmdline"]):
            info = proc.info
            out[info["pid"]] = (info.get("name") or "", " ".join(info.get("cmdline") or []))
        return out

    def connections(self, pids) -> list[dict]:
        rows = []
        for pid in pids:
            try:
                proc = self.psutil.Process(pid)
                conns = proc.net_connections(kind="inet") if hasattr(proc, "net_connections") else proc.connections(kind="inet")
            except (self.psutil.Error, OSError):
                continue
            for c in conns:
                proto = "udp" if c.type == 2 else "tcp"
                rows.append({"pid": pid, "proto": proto,
                             "laddr": (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0),
                             "raddr": (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0), "status": c.status})
        return rows


class CommandSource:
    """netstat / ss / tasklist / ps through subprocess; no third-party package needed."""

    def __init__(self):
        if os.name == "nt":
            self.name = "netstat"
        elif sys.platform.startswith("linux"):
            self.name = "ss"
        else:
            raise RuntimeError("no connection source for this platform without psutil (pip install psutil)")

    def processes(self) -> dict[int, tuple[str, str]]:
        if os.name == "nt":
            return parse_tasklist_csv(_run(["tasklist", "/FO", "CSV", "/NH"]))
        return parse_ps(_run(["ps", "-eo", "pid=,comm=,args="]))

    def connections(self, pids) -> list[dict]:
        rows = parse_netstat_windows(_run(["netstat", "-ano", "-p", "tcp"])) if os.name == "nt" \
            else parse_ss(_run(["ss", "-tnpH"]))
        wanted = set(pids)
        return [r for r in rows if r["pid"] in wanted]


def make_source():
    try:
        return PsutilSource()
    except ImportError:
        return CommandSource()


# -- the sampler -------------------------------------------------------------------------------

def _stem(name: str) -> str:
    return re.sub(r"\.exe$", "", (name or "").lower())


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified


def reverse_dns(ip: str, timeout: float = 1.5) -> str:
    import socket
    result: list[str] = []

    def work():
        try:
            result.append(socket.gethostbyaddr(ip)[0].lower())
        except (OSError, UnicodeError):
            pass

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    return result[0] if result else ""


class ConnectionSampler:
    """Same interface as canary.monitor.Monitor (status, events) plus start/stop/poll_once."""

    def __init__(self, process_names=(), cmdline_hints=(), pids=(), interval: float = 1.0, resolve: bool = True,
                 source=None, resolver=reverse_dns, clock=time.time, own_pid: int | None = None):
        self.names = {_stem(n) for n in process_names if n}
        self.hints = [h.lower() for h in cmdline_hints if h]
        self.pids = {int(p) for p in pids}
        self.interval = max(0.2, float(interval))
        self.resolve = resolve
        self.source = source
        self.resolver = resolver
        self.clock = clock
        self.own_pid = os.getpid() if own_pid is None else own_pid
        self._events: list[dict] = []
        self._seen: dict[tuple, float] = {}
        self._watched: dict[int, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._error = ""
        self.polls = 0

    def describe(self) -> str:
        return "builtin"

    # -- selection ---------------------------------------------------------------------------

    def _select(self, table: dict[int, tuple[str, str]]) -> dict[int, str]:
        chosen = {}
        ancestors = {self.own_pid}
        for pid, (name, cmd) in table.items():
            if pid in ancestors:
                continue
            low = cmd.lower()
            if pid in self.pids or _stem(name) in self.names or any(h in low for h in self.hints):
                if "-m canary" in low or "openweight-canary" in low:
                    continue                                    # never watch this tool itself
                chosen[pid] = name or str(pid)
        for pid in self.pids:
            chosen.setdefault(pid, table.get(pid, ("", ""))[0] or str(pid))
        return chosen

    # -- sampling ----------------------------------------------------------------------------

    def poll_once(self) -> list[dict]:
        if self.source is None:
            self.source = make_source()
        now = self.clock()
        try:
            watched = self._select(self.source.processes())
            rows = self.source.connections(list(watched)) if watched else []
            self._error = ""
        except Exception as exc:                                # a failed poll never stops the test
            self._error = f"{type(exc).__name__}: {exc}"
            log.warning("netwatch poll failed: %s", self._error)
            return []
        self.polls += 1
        self._watched = watched
        listening = {r["laddr"][1] for r in rows if r["status"] == "LISTEN"}
        new = []
        for row in rows:
            ip, port = row["raddr"]
            if not ip:
                continue
            if row["laddr"][1] in listening:
                continue                                        # a client talking to the watched server
            if _is_private(ip) and port not in PROXY_PORTS:
                continue
            key = (row["pid"], row["proto"], ip, port)
            with self._lock:
                last = self._seen.get(key)
                if last is not None and now - last < FORGET_AFTER_S:
                    continue
                self._seen[key] = now
            tags = ["local_proxy_port"] if _is_private(ip) else []
            event = {"id": uuid.uuid4().hex[:12], "ts": now, "kind": "network", "pid": row["pid"],
                     "process": _stem(watched.get(row["pid"], "")), "role": "engine", "proto": row["proto"],
                     "remote_ip": ip, "remote_port": port, "host": ip, "host_source": "ip",
                     "local": f"{row['laddr'][0]}:{row['laddr'][1]}", "status": row["status"], "tags": tags,
                     "suspicious": False}
            with self._lock:
                self._events.append(event)
                del self._events[:-MAX_EVENTS]
            new.append(event)
            if self.resolve and not _is_private(ip):
                threading.Thread(target=self._resolve, args=(event,), daemon=True).start()
        with self._lock:
            for key in [k for k, t in self._seen.items() if now - t > FORGET_AFTER_S]:
                del self._seen[key]
        return new

    def _resolve(self, event: dict) -> None:
        name = self.resolver(event["remote_ip"])
        if name:
            event["host"] = name
            event["host_source"] = "ptr"

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.interval)

    def start(self) -> "ConnectionSampler":
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="netwatch", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- Monitor-compatible reads --------------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            count = len(self._events)
        return {"enabled": True, "running": self._thread is not None and self._thread.is_alive(),
                "monitor": "openweight-canary built-in netwatch",
                "source": getattr(self.source, "name", "none"), "interval_s": self.interval,
                "watched": [{"pid": p, "name": n} for p, n in sorted(self._watched.items())],
                "polls": self.polls, "events": count, "last_error": self._error, "coverage": COVERAGE_NOTE}

    def events(self, since: float = 0.0, only: str = "all") -> list[dict]:
        with self._lock:
            rows = [dict(e) for e in self._events if e["ts"] > since]
        return [e for e in rows if only != "suspicious" or e.get("suspicious")]


# -- HTTP server (python -m canary netwatch) -----------------------------------------------------

def make_handler(sampler: ConnectionSampler, api_key: str = ""):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if api_key and self.headers.get("Authorization") != f"Bearer {api_key}":
                return self._send(401, {"error": "unauthorized"})
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if url.path in ("/api/netwatch/status", "/api/netwatch"):
                return self._send(200, sampler.status())
            if url.path == "/api/netwatch/events":
                try:
                    since = float(query.get("since", ["0"])[0])
                except ValueError:
                    return self._send(400, {"error": "since is a number"})
                events = sampler.events(since, query.get("only", ["all"])[0])
                return self._send(200, {"events": events, "total": len(events)})
            return self._send(404, {"error": "not found"})

    return Handler


def serve(sampler: ConnectionSampler, host: str = "127.0.0.1", port: int = 8098, api_key: str = "") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(sampler, api_key))
    threading.Thread(target=server.serve_forever, name="netwatch-http", daemon=True).start()
    return server


def sampler_from_spec(spec: dict, runtime: dict | None = None) -> ConnectionSampler:
    """Build a sampler from a network_watch object plus the runtime's defaults."""
    runtime = runtime or {}
    return ConnectionSampler(
        process_names=spec.get("process_names") or runtime.get("process_names") or [],
        cmdline_hints=spec.get("cmdline_hints") or runtime.get("cmdline_hints") or [],
        pids=spec.get("pids") or [], interval=spec.get("interval", 1.0), resolve=spec.get("resolve", True))

