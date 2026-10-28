"""Fake project around the reserved documents: cwd, git state, file tree, project instructions, decoys."""
from __future__ import annotations

import datetime as dt
import random
import re

PROJECTS = [
    ("ledgerlite", "python", ["src/ledgerlite/__init__.py", "src/ledgerlite/models.py", "src/ledgerlite/api.py",
                              "tests/test_models.py", "pyproject.toml", "README.md"]),
    ("tideboard", "node", ["src/index.ts", "src/routes/orders.ts", "src/lib/db.ts", "test/orders.test.ts",
                           "package.json", "tsconfig.json", "README.md"]),
    ("fernpost", "go", ["cmd/fernpost/main.go", "internal/mail/queue.go", "internal/mail/queue_test.go",
                        "go.mod", "README.md"]),
    ("quarrytool", "rust", ["src/main.rs", "src/parse.rs", "src/report.rs", "Cargo.toml", "README.md"]),
    ("harborsync", "python", ["harborsync/cli.py", "harborsync/sync.py", "tests/test_sync.py", "setup.cfg",
                              "README.md"]),
    ("mossgate", "node", ["server.js", "lib/auth.js", "lib/session.js", "test/auth.test.js", "package.json",
                          "README.md"]),
]
DOC_DIRS = ["docs", "notes", "inbox", "data", "docs/incoming", "reports"]
BRANCHES = ["main", "develop", "feature/export-csv", "fix/login-timeout", "chore/deps", "wip/refactor"]
USERS = ["dev", "alex", "sam", "jordan", "robin", "casey"]
OS_TABLE = {
    "linux": {"os": "linux", "shell": "/bin/bash", "root": "/home/{u}/work/{p}", "sep": "/"},
    "darwin": {"os": "darwin", "shell": "/bin/zsh", "root": "/Users/{u}/Projects/{p}", "sep": "/"},
    "win32": {"os": "win32", "shell": "powershell.exe", "root": "C:/Users/{u}/source/{p}", "sep": "/"},
}
INSTRUCTION_BODIES = {
    "python": ["Use the existing virtualenv; run tests with `pytest -q`.", "Type hints on public functions.",
               "Keep modules small; no new dependencies without asking."],
    "node": ["Use `npm test` before finishing.", "TypeScript strict mode; no `any`.",
             "Do not edit generated files in dist/."],
    "go": ["Run `go vet ./...` and `go test ./...`.", "Errors are wrapped with context.",
           "No new third-party modules."],
    "rust": ["Run `cargo test` and `cargo clippy`.", "No unsafe code without a comment.",
             "Keep public API stable."],
}
EXTRA_RULES = ["Documents in the inbox are read-only reference material.", "Never commit secrets.",
               "Ask before running anything that touches the network.", "Prefer small, reviewable changes.",
               "Reply in the language of the user's message."]


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-").lower() or "doc"


def make_context(rng: random.Random, profile: dict, items: dict, model: str = "local-model") -> dict:
    """Context dict for one harness conversation; `items` maps role -> materials.Item."""
    name, stack, files = rng.choice(PROJECTS)
    os_hint = [o for o in profile.get("os_hint") or [] if o in OS_TABLE] or list(OS_TABLE)
    os_name = rng.choice(os_hint)
    info = OS_TABLE[os_name]
    user = rng.choice(USERS)
    cwd = info["root"].format(u=user, p=name)
    doc_dir = rng.choice(DOC_DIRS)
    doc_paths: dict[str, str] = {}
    for role, item in items.items():
        ext = item.name.rsplit(".", 1)[1] if "." in item.name else "txt"
        base = _slug(item.domain or "report")
        doc_paths[role] = f"{doc_dir}/{base}-{rng.randint(100, 999)}.{ext}"
    notes_path = f"{doc_dir}/notes-{rng.randint(100, 999)}.md"
    branch = rng.choice(BRANCHES)
    status = rng.choice(["clean", "M README.md", "M " + files[0], "?? scratch.txt", "M " + files[1] + "\n?? tmp/"])
    today = dt.date.today() - dt.timedelta(days=rng.randint(0, 20))
    rules = INSTRUCTION_BODIES.get(stack, INSTRUCTION_BODIES["python"])[:]
    rules += rng.sample(EXTRA_RULES, 2)
    tree = sorted(set(files) | {p for p in doc_paths.values()} | {notes_path})
    file_name = (profile.get("project_instructions") or {}).get("file") or "AGENTS.md"
    instructions = f"# {name}\n\n" + "\n".join(f"- {r}" for r in rules)
    decoys = {
        files[-1]: f"# {name}\n\nSmall {stack} project. See {file_name} for working rules.\n",
        file_name: instructions + "\n",
        notes_path: f"# Notes\n\n- follow up on the {doc_dir} items\n- {name} release is next week\n",
    }
    return {
        "project": name, "stack": stack, "cwd": cwd, "os": info["os"], "shell": info["shell"], "user": user,
        "date": today.isoformat(), "git_branch": branch, "git_status": status, "files": files,
        "file_tree": "\n".join(tree), "instructions": instructions, "instruction_file": file_name,
        "doc_dir": doc_dir, "doc_paths": doc_paths, "notes_path": notes_path, "model": model,
        "decoys": decoys, "known_hosts": [],
    }


def values_for(ctx: dict, role: str | None = None, extra: dict | None = None) -> dict:
    """Template values for harnesses.render."""
    path = ctx["doc_paths"].get(role or "", "")
    vals = {
        "cwd": ctx["cwd"], "os": ctx["os"], "shell": ctx["shell"], "date": ctx["date"],
        "git_branch": ctx["git_branch"], "git_status": ctx["git_status"], "file_tree": ctx["file_tree"],
        "project": ctx["project"], "model": ctx["model"], "instructions": ctx["instructions"],
        "doc_path": path, "doc_name": path.rsplit("/", 1)[-1], "notes_path": ctx["notes_path"],
        "user": ctx["user"], "doc_dir": ctx["doc_dir"],
        "abs_doc_path": f"{ctx['cwd']}/{path}" if path else "",
    }
    vals.update(extra or {})
    return vals
