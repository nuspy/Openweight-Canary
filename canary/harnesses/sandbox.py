"""Fake tool world: serves the reserved documents and records every other call without running it."""
from __future__ import annotations

import datetime as dt
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
        hit = self.docs.get(self._path(raw).lower()) or self._invent(raw)
        if hit:
            self.touched.add(hit[0])
        return hit

    def _invent(self, raw: str):
        """The content of a file the model asked for that the computer did not list: made up once, coherent with the
        workspace, kept for the rest of the conversation."""
        ws = self.ctx.get("workspace")
        made = getattr(ws, "invent", None)
        if made is None or outside_project(raw, self.ctx["cwd"]):
            return None
        path = self._path(raw)
        got = made(path)
        if got is None:
            return None
        text, kind = got
        self.docs[path.lower()] = (path, text)
        ws.docs[path], ws.kinds[path] = text, kind
        return self.docs[path.lower()]

    def _store(self, raw: str, text: str, append: bool = False) -> None:
        if outside_project(raw, self.ctx["cwd"]):
            return
        path = self._path(raw)
        old = self.docs.get(path.lower())
        self.docs[path.lower()] = (path, (old[1] if old and append else "") + text)

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
        return self._compound(cmd)

    def _compound(self, cmd: str) -> str:
        """Each command of `a; b && c || d` answers in turn, as a shell prints them; a silent shell prints only the exit code.
        A bare number is a timeout the profile appended, not a command."""
        outs = [self._pipeline(seq) for seq in _split_top(cmd, ("&&", "||", ";", "\n")) if not seq.isdigit()]
        return "\n".join(o for o in outs if o) or "[exit code: 0]"

    def _pipeline(self, seq: str) -> str:
        segs = _split_top(seq, ("|",))
        out = self._simple(segs[0]) if segs else ""
        for seg in segs[1:]:
            out = _filter(seg, out)
        return out

    def _simple(self, cmd: str) -> str:
        words = cmd.split()
        first = words[0] if words else ""
        written = self._redirect(cmd)
        if written is not None:
            return written
        if first == "pwd":
            return self.ctx["cwd"]
        if first == "echo":
            return cmd[len(first):].strip().strip("\"'")
        facts = self._facts(first, words, cmd)
        if facts is not None:
            return facts
        if self.has_workspace and first in ("ls", "dir"):
            return self.tree().ls(cmd)
        if self.has_workspace and first == "find":
            return self.tree().find(cmd)
        if self.has_workspace and first == "tree":
            return self.tree().tree(cmd)
        if first in ("ls", "dir", "tree"):
            return self.listing({})
        if cmd.startswith("git status"):
            return f"On branch {self.ctx['git_branch']}\n{self.ctx['git_status']}"
        if first in ("cat", "type", "head", "tail", "less", "more", "nl", "wc", "grep", "rg", "stat", "file"):
            for raw in re.findall(r"[^\s|<>;&]+\.[A-Za-z0-9]{1,5}\b|[^\s|<>;&]*(?:akefile|ockerfile|ICENSE|\.gitignore)", cmd):
                hit = self._lookup(raw)
                if hit:
                    return self._file_answer(first, cmd, hit)
            if self.has_workspace and first in ("grep", "rg"):
                words = [t for t in cmd.split()[1:] if not t.startswith("-")]
                return self.grep({"pattern": words[0].strip("\"'")}) if words else "No matches found"
            target = next((t for t in cmd.split()[1:] if not t.startswith("-")), "")
            return f"{first}: {target}: No such file or directory" if target else "No such file or directory"
        return ""

    def _file_answer(self, first: str, cmd: str, hit) -> str:
        path, text = hit
        if first == "wc":
            lines, size = len(text.splitlines()), len(text.encode("utf-8"))
            flags = [w for w in cmd.split()[1:] if w.startswith("-")]
            if "-l" in flags:
                return f"{lines} {path}"
            if "-c" in flags:
                return f"{size} {path}"
            if "-w" in flags:
                return f"{len(text.split())} {path}"
            return f"{lines} {len(text.split())} {size} {path}"
        if first in ("head", "tail"):
            return _filter(" ".join(w for w in cmd.split() if w == first or w.startswith("-") or w.isdigit()), text[:MAX_READ])
        if first == "stat":
            return f"  File: {path}\n  Size: {len(text.encode('utf-8'))}\tRegular file\nAccess: (0644/-rw-r--r--)  Uid: ( 1000/{self.ctx['user']})"
        if first == "file":
            return f"{path}: ASCII text"
        return text[:MAX_READ]

    def _redirect(self, cmd: str):
        """`echo text > file` and `>>`: the file now holds the text (in this conversation only)."""
        m = re.match(r"^(?:echo|printf)\s+(.*?)\s*(>>?)\s*([^\s>|]+)\s*$", cmd)
        if not m:
            return None
        self._store(m.group(3), m.group(1).strip().strip("\"'") + "\n", append=m.group(2) == ">>")
        return ""

    def _stamp(self, back: int = 0) -> dt.datetime:
        day = dt.date.fromisoformat(self.ctx["date"]) - dt.timedelta(days=back)
        return dt.datetime(day.year, day.month, day.day, 9, 14, 2)

    def _facts(self, first: str, words: list[str], cmd: str):
        """Answers of the small commands that say something about the machine; None when `first` is not one of them."""
        user, win = self.ctx["user"], str(self.ctx.get("os", "")).lower().startswith("win")
        host = f"{user}-laptop"
        if first in ("cd", "mkdir", "chmod", "export", "source", "set", "clear", "sleep", "true"):
            return ""
        if first == "touch":
            for raw in words[1:]:
                if not raw.startswith("-") and not self.docs.get(self._path(raw).lower()):
                    self._store(raw, "")
            return ""
        if first in ("rm", "del"):
            out = []
            for raw in (w for w in words[1:] if not w.startswith("-")):
                key = self._path(raw).lower()
                if key in self.docs:
                    del self.docs[key]
                else:
                    out.append(f"rm: cannot remove '{raw}': No such file or directory")
            return "\n".join(out)
        if first in ("cp", "mv", "copy", "move"):
            args = [w for w in words[1:] if not w.startswith("-")]
            hit = self._lookup(args[0]) if len(args) == 2 else None
            if len(args) == 2 and hit:
                self._store(args[1], hit[1])
                if first in ("mv", "move"):
                    self.docs.pop(self._path(args[0]).lower(), None)
                return ""
            return f"{first}: cannot stat '{args[0]}': No such file or directory" if args else ""
        if win:
            return None
        day = self._stamp()
        if first == "date":
            return day.strftime("%a %b %e %H:%M:%S UTC %Y").replace("  ", " ")
        if first == "whoami":
            return user
        if first == "id":
            return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)"
        if first == "hostname":
            return host
        if first == "uname":
            return f"Linux {host} 6.5.0-35-generic #35-Ubuntu SMP x86_64 GNU/Linux" if "-a" in words else "Linux"
        if first == "uptime":
            return " 09:14:02 up 3 days,  4:21,  1 user,  load average: 0.21, 0.18, 0.15"
        if first in ("python", "python3") and any(w in ("--version", "-V") for w in words):
            return "Python 3.11.6"
        if first == "node" and any(w in ("-v", "--version") for w in words):
            return "v20.11.1"
        if first == "which" and len(words) > 1:
            return f"/usr/bin/{words[1]}"
        if first == "df":
            return ("Filesystem      Size  Used Avail Use% Mounted on\n/dev/nvme0n1p2  468G  211G  234G  48% /\n"
                    "tmpfs            16G  1.2M   16G   1% /run")
        if first == "ps":
            return (f"USER         PID %CPU %MEM COMMAND\n{user}      1204  0.1  0.4 bash\n{user}      2310  0.0  0.2 ps\n"
                    f"root         811  0.0  0.1 /usr/sbin/cron")
        if first in ("env", "printenv"):
            return (f"USER={user}\nHOME=/home/{user}\nSHELL=/bin/bash\nPWD={self.ctx['cwd']}\nLANG=en_US.UTF-8\n"
                    "PATH=/usr/local/bin:/usr/bin:/bin")
        if first == "du":
            total = sum(len(t.encode("utf-8")) for _, t in self.docs.values())
            return f"{max(1, total // 1024)}K\t."
        if first == "git":
            sub = words[1] if len(words) > 1 else ""
            if sub == "--version":
                return "git version 2.43.0"
            if sub == "branch":
                return f"* {self.ctx['git_branch']}"
            if sub in ("diff", "stash", "fetch", "pull"):
                return ""
            if sub == "log":
                import hashlib
                msgs = ("Update notes", "Fix typo in the readme", "Initial commit")
                one = "--oneline" in words
                out = []
                for i, msg in enumerate(msgs):
                    h = hashlib.sha1(f"{self.ctx['date']}{i}".encode()).hexdigest()
                    when = self._stamp(3 * i).strftime("%a %b %e %H:%M:%S %Y +0000").replace("  ", " ")
                    out.append(f"{h[:7]} {msg}" if one else f"commit {h}\nAuthor: {user} <{user}@{host}>\nDate:   {when}\n\n    {msg}\n")
                return "\n".join(out)
        return None

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
            body = next((v for k, v in args.items() if k in ("content", "text", "file_text", "data", "contents") and isinstance(v, str)), None)
            if role == "write" and body is not None:
                for raw in tool_paths(args)[:1]:
                    self._store(raw, body)
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


def _split_top(text: str, ops: tuple) -> list[str]:
    """`text` cut at the operators that are not inside quotes."""
    parts, cur, quote, i = [], [], "", 0
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            quote = "" if ch == quote else quote
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
            i += 1
            continue
        hit = next((o for o in ops if text.startswith(o, i)), None)
        if hit:
            parts.append("".join(cur))
            cur = []
            i += len(hit)
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _filter(seg: str, text: str) -> str:
    """What the tools at the end of a pipe do to the text they receive."""
    words = seg.split()
    name, flags = (words[0] if words else ""), [w for w in words[1:] if w.startswith("-")]
    rest = [w for w in words[1:] if not w.startswith("-")]
    lines = text.splitlines()
    count = next((int(w[1:]) for w in flags if w[1:].isdigit()), None)
    if count is None and "-n" in words:
        at = words.index("-n") + 1
        count = int(words[at]) if at < len(words) and words[at].isdigit() else None
    count = 10 if count is None else count
    if name == "wc":
        if "-l" in flags:
            return str(len(lines))
        if "-c" in flags:
            return str(len(text.encode("utf-8")))
        if "-w" in flags:
            return str(len(text.split()))
        return f"{len(lines)} {len(text.split())} {len(text.encode('utf-8'))}"
    if name == "head":
        return "\n".join(lines[:count])
    if name == "tail":
        return "\n".join(lines[-count:] if count else [])
    if name in ("grep", "rg") and rest:
        pat = rest[0].strip("\"'")
        try:
            rx = re.compile(pat, re.I if "-i" in flags else 0)
        except re.error:
            rx = re.compile(re.escape(pat))
        hits = [ln for ln in lines if bool(rx.search(ln)) != ("-v" in flags)]
        return str(len(hits)) if "-c" in flags else "\n".join(hits)
    if name == "sort":
        return "\n".join(sorted(lines, reverse="-r" in flags))
    if name == "uniq":
        return "\n".join(ln for i, ln in enumerate(lines) if i == 0 or ln != lines[i - 1])
    return text
