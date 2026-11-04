"""Directory answers of the fake computer: `ls`, `find`, `tree` and one-level listings, from the paths and sizes of the fake files."""
from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import shlex

SKIP = ("-",)


class Tree:
    def __init__(self, files: dict[str, int], user: str, date: str):
        self.files, self.user, self.date = files, user, date
        self.dirs = {"."}
        for path in files:
            parts = path.split("/")
            for i in range(1, len(parts)):
                self.dirs.add("/".join(parts[:i]))

    # -- structure

    def _clean(self, path: str) -> str:
        p = (path or ".").strip().strip("\"'").replace("\\", "/")
        while p.startswith("./"):
            p = p[2:]
        return p.rstrip("/") or "."

    def kind(self, path: str) -> str | None:
        p = self._clean(path)
        return "dir" if p in self.dirs else "file" if p in self.files else None

    def children(self, path: str) -> tuple[list[str], list[str]]:
        base = self._clean(path)
        prefix = "" if base == "." else base + "/"
        dirs, files = set(), set()
        for name in self.files:
            if prefix and not name.startswith(prefix):
                continue
            head, _, tail = name[len(prefix):].partition("/")
            (dirs if tail else files).add(head)
        return sorted(dirs, key=str.lower), sorted(files, key=str.lower)

    def under(self, path: str) -> list[str]:
        base = self._clean(path)
        prefix = "" if base == "." else base + "/"
        return sorted((n for n in self.files if n.startswith(prefix)), key=str.lower)

    def _stamp(self, name: str) -> str:
        h = int(hashlib.sha256(name.encode()).hexdigest()[:8], 16)
        day = dt.date.fromisoformat(self.date) - dt.timedelta(days=h % 40)
        return f"{day.strftime('%b %d')} {h % 24:02d}:{(h // 24) % 60:02d}"

    def _line(self, name: str, full: str, is_dir: bool) -> str:
        size = 4096 if is_dir else self.files.get(full, 0)
        mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
        return f"{mode} {2 if is_dir else 1} {self.user} {self.user} {size:>7} {self._stamp(full)} {name}"

    # -- commands

    def ls(self, command: str) -> str:
        try:
            tokens = shlex.split(command, posix=True)[1:]
        except ValueError:
            tokens = command.split()[1:]
        flags = "".join(t[1:] for t in tokens if t.startswith("-") and not t.startswith("--"))
        paths = [t for t in tokens if not t.startswith("-")] or ["."]
        long, hidden, recursive = "l" in flags, "a" in flags or "A" in flags, "R" in flags
        out: list[str] = []
        for path in paths:
            kind = self.kind(path)
            if kind is None:
                out.append(f"ls: cannot access '{path}': No such file or directory")
                continue
            if len(paths) > 1:
                out.append(f"{path}:")
            if kind == "file":
                out.append(self._line(path, self._clean(path), False) if long else path)
                continue
            out += self._dir_lines(self._clean(path), long, hidden)
            if recursive:
                for sub in sorted(d for d in self.dirs if d.startswith("" if path in (".", "") else self._clean(path) + "/")):
                    out += ["", f"./{sub}:"] + self._dir_lines(sub, long, hidden)
        return "\n".join(out)

    def _dir_lines(self, path: str, long: bool, hidden: bool) -> list[str]:
        dirs, files = self.children(path)
        names = [(d, True) for d in dirs] + [(f, False) for f in files]
        names.sort(key=lambda x: x[0].lower())
        if hidden:
            names = [(".", True), ("..", True)] + names
        base = "" if path == "." else path + "/"
        if long:
            return [f"total {sum(4 if d else max(1, self.files.get(base + n, 0) // 1024) for n, d in names)}"] + \
                   [self._line(n, base + n, d) for n, d in names]
        return [n for n, _ in names]

    def find(self, command: str) -> str:
        try:
            tokens = shlex.split(command, posix=True)[1:]
        except ValueError:
            tokens = command.split()[1:]
        start = next((t for t in tokens if not t.startswith("-")), ".")
        pattern = kind = None
        for i, t in enumerate(tokens):
            if t in ("-name", "-iname") and i + 1 < len(tokens):
                pattern = tokens[i + 1]
            if t == "-type" and i + 1 < len(tokens):
                kind = tokens[i + 1]
        if self.kind(start) is None:
            return f"find: '{start}': No such file or directory"
        base = self._clean(start)
        prefix = "" if base == "." else base + "/"
        rows = [(d, True) for d in sorted(self.dirs) if d != "." and (not prefix or d.startswith(prefix) or d == base)] + [(f, False) for f in self.under(base)]
        out = [base] if kind in (None, "d") and not pattern else []
        for name, is_dir in sorted(rows, key=lambda r: r[0].lower()):
            if kind == "f" and is_dir or kind == "d" and not is_dir:
                continue
            if pattern and not fnmatch.fnmatch(name.rsplit("/", 1)[-1], pattern):
                continue
            if name == base:
                continue
            out.append(("./" + name) if base == "." else name)
        return "\n".join(out)

    def tree(self, command: str) -> str:
        parts = command.split()[1:]
        start = next((t for t in parts if not t.startswith("-")), ".")
        if self.kind(start) != "dir":
            return f"{start} [error opening dir]"
        lines = [start]
        counts = [0, 0]

        def walk(path: str, indent: str) -> None:
            dirs, files = self.children(path)
            entries = [(d, True) for d in dirs] + [(f, False) for f in files]
            for i, (name, is_dir) in enumerate(entries):
                last = i == len(entries) - 1
                lines.append(f"{indent}{'└── ' if last else '├── '}{name}")
                if is_dir:
                    counts[0] += 1
                    walk(name if path == "." else f"{path}/{name}", indent + ("    " if last else "│   "))
                else:
                    counts[1] += 1
        walk(self._clean(start), "")
        return "\n".join(lines + ["", f"{counts[0]} directories, {counts[1]} files"])

    def one_level(self, path: str) -> str:
        """The listing a list-directory tool gives: folders with a trailing slash, then files."""
        if self.kind(path) != "dir":
            return f"Error: not a directory: {path}"
        dirs, files = self.children(path)
        return "\n".join([d + "/" for d in dirs] + files) or "(empty)"
