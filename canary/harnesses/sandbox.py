"""Fake tool world: serves the reserved documents and records every other call without running it."""
from __future__ import annotations

import fnmatch
import json
import re

from ..detect import classify_shell, norm_path, outside_project, tool_commands, tool_paths, tool_urls
from ..util import host_of
from .fixtures import Fixtures, document_facts
from .vfs import Tree

NOT_FOUND = "Error: file not found: {path}"
OUTSIDE = "Error: path is outside the workspace: {path}"
MAX_READ = 6000
MAX_GREP = 25
FIXTURE_ROLES = ("email_read", "email_send", "process", "registry_read", "registry_write", "calendar_read")


class FakeWorld:
    """Nothing here touches the disk, the network or a shell; calls other than reads are only recorded."""

    def __init__(self, ctx: dict, docs: dict[str, str], read_format: str = "numbered", item=None,
                 results: dict[str, str] | None = None):
        self.ctx = ctx
        self.results = results or {}
        self.fixtures = Fixtures(ctx, document_facts(item)) if item is not None else None
        self.docs = {norm_path(p, ctx["cwd"]).lower(): (p, t) for p, t in docs.items()}
        for path, text in ctx.get("decoys", {}).items():
            self.docs.setdefault(norm_path(path, ctx["cwd"]).lower(), (path, text))
        ws = ctx.get("workspace")
        for path, text in (ws.docs if ws else {}).items():
            self.docs.setdefault(norm_path(path, ctx["cwd"]).lower(), (path, text))
        self.read_format = read_format
        self.recorded: list[dict] = []
        self.has_workspace = bool(ws)
        self.touched: set[str] = set()

    # -- helpers

    def _path(self, raw: str) -> str:
        return norm_path(raw, self.ctx["cwd"])

    def _lookup(self, raw: str):
        hit = self.docs.get(self._path(raw).lower())
        if hit:
            self.touched.add(hit[0])
        return hit

    def tree(self) -> Tree:
        files = {p: len(t.encode("utf-8")) for p, t in self.docs.values()}
        files.update({f: 0 for f in self.ctx["files"] if f not in files})
        return Tree(files, self.ctx["user"], self.ctx["date"])

    def format_file(self, path: str, text: str) -> str:
        text = text[:MAX_READ]
        if self.read_format == "numbered":
            return "\n".join(f"{i:>6}\t{line}" for i, line in enumerate(text.splitlines(), 1))
        if self.read_format == "pipe":
            return "\n".join(f"{i:>6}|{line}" for i, line in enumerate(text.splitlines(), 1))
        if self.read_format == "xml":
            return f"<file path=\"{path}\">\n{text}\n</file>"
        return text

    def _record(self, role: str, name: str, args, note: str = "") -> None:
        self.recorded.append({"role": role, "name": name, "arguments": args, "executed": False, "note": note})

    # -- tools

    def read(self, args) -> str:
        paths = tool_paths(args)
        if not paths:
            return "Error: no path given"
        out = []
        for raw in paths:
            if outside_project(raw, self.ctx["cwd"]):
                out.append(OUTSIDE.format(path=raw))
                continue
            hit = self._lookup(raw)
            out.append(self.format_file(hit[0], hit[1]) if hit else NOT_FOUND.format(path=raw))
        return "\n\n".join(out) if len(out) > 1 else out[0]

    def listing(self, args) -> str:
        pattern_given = any(k in (args or {}) and isinstance(v, str) and v not in ("", "*", "**/*") for k, v in (args or {}).items()
                            if k in ("pattern", "glob", "include", "query"))
        if self.has_workspace and not pattern_given:
            base = next(iter(tool_paths(args)), ".")
            return self.tree().one_level(self._path(base) if base else ".")
        names = sorted({p for p, _ in self.docs.values()} | set(self.ctx["files"]))
        pattern = next((v for k, v in (args or {}).items()
                        if k in ("pattern", "glob", "include", "query") and isinstance(v, str)), "")
        base = next(iter(tool_paths(args)), "")
        if base and base not in (".", "./"):
            prefix = self._path(base).rstrip("/") + "/"
            names = [n for n in names if n.lower().startswith(prefix.lower())] or names
        if pattern and pattern not in ("*", "**/*"):
            names = [n for n in names if fnmatch.fnmatch(n, pattern) or fnmatch.fnmatch(n.rsplit("/", 1)[-1], pattern)]
        return "\n".join(names) if names else "No files found"

    def grep(self, args) -> str:
        pat = next((v for k, v in (args or {}).items()
                    if k in ("pattern", "query", "regex", "search", "text") and isinstance(v, str)), "")
        if not pat:
            return "Error: no pattern"
        try:
            rx = re.compile(pat, re.I)
        except re.error:
            rx = re.compile(re.escape(pat), re.I)
        hits = []
        for path, text in self.docs.values():
            for i, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{path}:{i}:{line[:160]}")
        return "\n".join(hits[:MAX_GREP]) or "No matches found"

    def shell(self, args) -> str:
        cmd = (tool_commands(args) or [""])[0] if not isinstance(args.get("commands"), list) \
            else "\n".join(str(c) for c in args["commands"])
        cls = classify_shell(cmd)["classes"]
        first = cmd.strip().split()[0] if cmd.strip() else ""
        self._record("shell", "shell", {"command": cmd}, ",".join(cls))
        if "net" in cls:
            host = next(iter(host_of(u) for u in tool_urls({"c": cmd})), "") or "host"
            return f"curl: (6) Could not resolve host: {host}\n[exit code: 6]"
        if first in ("pwd", "cd"):
            return self.ctx["cwd"]
        if self.has_workspace and first in ("ls", "dir"):
            return self.tree().ls(cmd.strip().split("\n")[0])
        if self.has_workspace and first == "find":
            return self.tree().find(cmd.strip().split("\n")[0])
        if self.has_workspace and first == "tree":
            return self.tree().tree(cmd.strip().split("\n")[0])
        if first in ("ls", "dir", "tree"):
            return self.listing({})
        if cmd.startswith("git status"):
            return f"On branch {self.ctx['git_branch']}\n{self.ctx['git_status']}"
        if first in ("cat", "type", "head", "tail", "less", "more", "nl", "wc", "grep", "rg"):
            for raw in re.findall(r"[^\s|<>;&]+\.[A-Za-z0-9]{1,5}\b", cmd):
                hit = self._lookup(raw)
                if hit:
                    return hit[1][:MAX_READ] if first != "wc" else f"{len(hit[1].splitlines())} {hit[0]}"
            if self.has_workspace and first in ("grep", "rg"):
                words = [t for t in cmd.split()[1:] if not t.startswith("-")]
                return self.grep({"pattern": words[0].strip("\"'")}) if words else "No matches found"
            return "No such file or directory"
        return "[exit code: 0]"

    def web(self, role: str, name: str, args) -> str:
        urls = tool_urls(args)
        self._record(role, name, args)
        if role == "web_fetch" and urls:
            return f"Fetched {urls[0]} (200 OK)\n\nExample Domain. This page is a placeholder."
        query = next((v for v in (args or {}).values() if isinstance(v, str)), "")
        hosts = ["docs.example.invalid", "wiki.example.invalid"]
        self.ctx.setdefault("known_hosts", []).extend(hosts)
        return "\n".join(f"{i}. Result for {query[:60]}: https://{h}/page{i}" for i, h in enumerate(hosts, 1))

    def run(self, role: str | None, name: str, args) -> str:
        args = args if isinstance(args, dict) else {"_raw": args}
        if role == "read":
            return self.read(args)
        if role in ("list", "glob"):
            return self.listing(args)
        if role == "grep":
            return self.listing(args) if args.get("target") == "files" else self.grep(args)
        if role == "shell":
            return self.shell(args)
        if role in ("web_fetch", "web_search"):
            return self.web(role, name, args)
        if role in ("write", "edit", "patch"):
            self._record(role, name, args)
            return self.results.get(name) or ("File written successfully." if role == "write" else "The edit was applied.")
        if role == "todo":
            return self.results.get(name, "Todo list updated.")
        if role == "ask_user":
            return self.results.get(name, "The user is not available; continue with your best judgement.")
        if role == "mcp":
            self._record(role, name, args)
            return self.results.get(name, "ok")
        if role in FIXTURE_ROLES:
            return self.fixture(role, name, args)
        if role == "finish":
            return "Done."
        self._record("unknown", name, args)
        return f"Error: unknown tool {name}"

    def fixture(self, role: str, name: str, args) -> str:
        """Mail, process, registry and calendar tools: invented answers; sends and writes are only recorded."""
        fx = self.fixtures
        if fx is None:
            return f"Error: {name} is not available"
        if role == "email_read":
            return fx.email_read(args)
        if role == "email_send":
            self._record(role, name, args, "recipients outside the mailbox: " + ",".join(fx.foreign_recipients(args)))
            return fx.email_send(args)
        if role == "calendar_read":
            return fx.calendar_read(args)
        if role == "registry_read":
            return fx.registry_read(args)
        if role == "registry_write":
            self._record(role, name, args, "in-memory only")
            return fx.registry_write(args)
        if args.get("action") is None:
            return fx.process_table(args)
        if args["action"] == "list":
            return json.dumps({"processes": []})
        self._record(role, name, args)
        return json.dumps({"error": "no such process session"})
