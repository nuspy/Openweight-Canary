"""Agent-harness profiles: what the prompts, tools and session start of common harnesses look like.

A profile is a JSON file in profiles/ (or in a directory given in the config key `harness_dir`). See
docs/harnesses.md for the fields and for how to add one.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

PROFILE_DIR = Path(__file__).with_name("profiles")
KINDS = ("private", "enterprise")
STATUSES = ("verified", "approximate")
TOOL_MODES = ("native", "react_text", "json_blob", "text_blocks")
ROLES = ("read", "write", "edit", "patch", "shell", "grep", "glob", "list", "web_fetch", "web_search",
         "ask_user", "todo", "mcp", "finish")
REQUIRED = ("id", "name", "kind", "status", "summary", "sources", "tool_mode", "system", "tools", "tasks")

_cache: dict[str, dict] = {}


class ProfileError(ValueError):
    pass


def validate(profile: dict) -> list[str]:
    """Problems found in one profile (empty list when it is usable)."""
    problems = [f"missing field {key!r}" for key in REQUIRED if key not in profile]
    if problems:
        return problems
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", profile["id"]):
        problems.append("id must be lowercase letters, digits and dashes")
    if profile["kind"] not in KINDS:
        problems.append(f"kind must be one of {KINDS}")
    if profile["status"] not in STATUSES:
        problems.append(f"status must be one of {STATUSES}")
    if profile["tool_mode"] not in TOOL_MODES:
        problems.append(f"tool_mode must be one of {TOOL_MODES}")
    if profile["status"] == "verified" and not profile.get("verified_parts"):
        problems.append("a verified profile must name verified_parts")
    if profile["status"] == "approximate" and not profile.get("approximate"):
        problems.append("an approximate profile must set approximate: true")
    if not profile["sources"] or not all(s.get("url") for s in profile["sources"]):
        problems.append("sources must list at least one url")
    if not profile["tasks"]:
        problems.append("tasks must not be empty")
    if profile["tool_mode"] != "text_blocks" and not profile["tools"]:
        problems.append("tools must not be empty")
    names = set()
    for tool in profile["tools"]:
        if tool.get("role") not in ROLES:
            problems.append(f"tool {tool.get('function', {}).get('name')!r}: role must be one of {ROLES}")
        fn = tool.get("function") or {}
        if not fn.get("name") or "parameters" not in fn:
            problems.append("every tool needs function.name and function.parameters")
        elif fn["name"] in names:
            problems.append(f"duplicate tool {fn['name']!r}")
        names.add(fn.get("name"))
    for task in profile["tasks"]:
        if "prompt" not in task:
            problems.append("every task needs a prompt")
    return problems


def _load_dir(directory: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted(Path(directory).glob("*.json")):
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProfileError(f"{path.name}: {exc}") from exc
        problems = validate(profile)
        if problems:
            raise ProfileError(f"{path.name}: " + "; ".join(problems))
        out[profile["id"]] = profile
    return out


def load_profiles(extra_dir: str | Path | None = None) -> dict[str, dict]:
    """All profiles by id; profiles in `extra_dir` add to or replace the built-in ones."""
    key = str(extra_dir or "")
    if key not in _cache:
        profiles = _load_dir(PROFILE_DIR)
        if extra_dir:
            profiles.update(_load_dir(Path(extra_dir)))
        _cache[key] = profiles
    return _cache[key]


def select(spec, extra_dir: str | Path | None = None) -> list[str]:
    """Profile ids for `all`, a comma separated string or a list; raises ProfileError on an unknown id."""
    profiles = load_profiles(extra_dir)
    if isinstance(spec, str):
        spec = [s for s in re.split(r"[,\s]+", spec) if s]
    spec = list(spec or [])
    if "all" in spec:
        return sorted(profiles)
    unknown = [s for s in spec if s not in profiles]
    if unknown:
        raise ProfileError(f"unknown harness {', '.join(unknown)}; run `python -m canary harnesses` for the list")
    seen: list[str] = []
    for s in spec:
        if s not in seen:
            seen.append(s)
    return seen


def listing(extra_dir: str | Path | None = None) -> list[dict]:
    """One summary row per profile, the shape `harnesses --json` prints."""
    rows = []
    for pid, p in sorted(load_profiles(extra_dir).items()):
        rows.append({
            "id": pid, "name": p["name"], "kind": p["kind"], "status": p["status"],
            "approximate": bool(p.get("approximate")), "tool_mode": p["tool_mode"],
            "verified_parts": p.get("verified_parts", []), "approximate_parts": p.get("approximate_parts", []),
            "source": p["sources"][0]["url"], "sources": [s["url"] for s in p["sources"]],
            "licence": p["sources"][0].get("licence", ""), "summary": p["summary"],
            "tools": [t["function"]["name"] for t in p["tools"]], "tasks": len(p["tasks"]),
        })
    return rows


def api_tools(profile: dict) -> list[dict]:
    """Tool schemas in OpenAI function-calling format (without the canary-only `role` key)."""
    return [{"type": "function", "function": t["function"]} for t in profile["tools"]]


def render(template: str, values: dict) -> str:
    """Replace <<key>> markers; unknown markers stay as they are."""
    return re.sub(r"<<(\w+)>>", lambda m: str(values.get(m.group(1), m.group(0))), template)
