"""Configuration: canary.json plus CLI overrides."""
from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .util import parse_duration, sha256_hex, canonical

DEFAULT_MARKERS = [
    "RESERVED", "PRESERVED", "SECRET", "TOP SECRET", "COSMIC TOP SECRET",
    "NATO SECRET", "NATO CONFIDENTIAL", "NATO RESTRICTED",
    "RISERVATISSIMO", "SEGRETO", "SEGRETISSIMO",
]
DEFAULT_DOMAINS = [
    "military", "semiconductor", "satellite", "diplomacy", "energy", "intelligence_liaison",
]
KINDS = ("openai", "anthropic")

PROVIDER_DEFAULT = {"kind": "openai", "base_url": "", "api_key": "", "model": "", "extra_headers": {}}

DEFAULTS = {
    "target": {**PROVIDER_DEFAULT, "base_url": "http://127.0.0.1:8080"},
    "generators": [],
    "reviewer": None,
    "monitor": None,
    "state_dir": "state",
    "duration": "until-stopped",
    "sessions_per_hour": 6,
    "seed": None,
    "canary_listener": {"enabled": False, "host": "127.0.0.1", "port": 8099, "public_base_url": ""},
    "markers": DEFAULT_MARKERS,
    "domains": DEFAULT_DOMAINS,
    "doc_words": 3000,
    "research_share": 0.5,
    "archive_share": 0.25,
    "public_share": 0.2,
    "max_tasks": 3,
    "review_every": 10,
    "max_tokens": 1024,
    "timeout": 600,
    "retries": 3,
    "backoff": 2.0,
    "monitor_grace": 2.0,
    "ab_delta_min_events": 3,
    "sources_file": "sources.json",
}


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    target: dict
    generators: list
    reviewer: dict | None
    monitor: dict | None
    state_dir: Path
    duration: float | None
    sessions_per_hour: float
    seed: int | None
    canary_listener: dict
    markers: list
    domains: list
    doc_words: int
    research_share: float
    archive_share: float
    public_share: float
    max_tasks: int
    review_every: int
    max_tokens: int
    timeout: float
    retries: int
    backoff: float
    monitor_grace: float
    ab_delta_min_events: int
    sources_file: Path

    def to_dict(self, redact: bool = True) -> dict:
        def scrub(spec):
            if spec is None:
                return None
            spec = dict(spec)
            if redact:
                spec["api_key"] = "***" if spec.get("api_key") else ""
                spec["extra_headers"] = {k: "***" for k in spec.get("extra_headers", {})}
            return spec

        return {
            "target": scrub(self.target),
            "generators": [scrub(g) for g in self.generators],
            "reviewer": scrub(self.reviewer),
            "monitor": scrub(self.monitor),
            "state_dir": str(self.state_dir),
            "duration": self.duration,
            "sessions_per_hour": self.sessions_per_hour,
            "seed": self.seed,
            "canary_listener": dict(self.canary_listener),
            "markers": list(self.markers),
            "domains": list(self.domains),
            "doc_words": self.doc_words,
            "research_share": self.research_share,
            "archive_share": self.archive_share,
            "public_share": self.public_share,
            "max_tasks": self.max_tasks,
            "review_every": self.review_every,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "retries": self.retries,
            "backoff": self.backoff,
            "monitor_grace": self.monitor_grace,
            "ab_delta_min_events": self.ab_delta_min_events,
            "sources_file": str(self.sources_file),
        }

    def hash(self) -> str:
        """Config identity for comparing runs; keys and state location excluded."""
        data = self.to_dict(redact=True)
        data.pop("state_dir")
        data.pop("sources_file")
        data.pop("duration")
        return sha256_hex(canonical(data))[:16]


def _secret(value: str) -> str:
    """'env:NAME' reads the key from the environment."""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value or ""


def _provider(raw, name: str, require_url: bool = True) -> dict:
    if not isinstance(raw, dict):
        raise ConfigError(f"{name}: must be an object")
    unknown = set(raw) - set(PROVIDER_DEFAULT)
    if unknown:
        raise ConfigError(f"{name}: unknown keys {sorted(unknown)}")
    spec = {**PROVIDER_DEFAULT, **raw}
    if spec["kind"] not in KINDS:
        raise ConfigError(f"{name}.kind must be one of {KINDS}")
    if require_url and not spec["base_url"]:
        raise ConfigError(f"{name}.base_url is required")
    spec["api_key"] = _secret(spec["api_key"])
    spec["extra_headers"] = {str(k): _secret(str(v)) for k, v in (spec["extra_headers"] or {}).items()}
    return spec


def build_config(raw: dict, base_dir: Path | None = None) -> Config:
    base_dir = Path(base_dir) if base_dir else Path.cwd()
    unknown = [k for k in raw if k not in DEFAULTS and not k.startswith("_")]
    if unknown:
        raise ConfigError(f"unknown config keys: {unknown}")
    data = copy.deepcopy(DEFAULTS)
    data.update({k: v for k, v in raw.items() if not k.startswith("_")})

    target = _provider(data["target"], "target")
    generators = [_provider(g, f"generators[{i}]") for i, g in enumerate(data["generators"] or [])]
    reviewer = _provider(data["reviewer"], "reviewer") if data["reviewer"] else None
    monitor = None
    if data["monitor"]:
        mon = data["monitor"]
        if not mon.get("base_url"):
            raise ConfigError("monitor.base_url is required")
        monitor = {"base_url": mon["base_url"], "api_key": _secret(mon.get("api_key", ""))}

    listener = {**DEFAULTS["canary_listener"], **(data["canary_listener"] or {})}
    try:
        duration = parse_duration(data["duration"])
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    if not data["markers"]:
        raise ConfigError("markers must not be empty")
    if not 0 <= data["research_share"] <= 1:
        raise ConfigError("research_share must be between 0 and 1")
    if data["doc_words"] < 100:
        raise ConfigError("doc_words must be at least 100")
    if not 1 <= data["max_tasks"] <= 3:
        raise ConfigError("max_tasks must be 1..3")

    def resolve(p) -> Path:
        p = Path(p)
        return p if p.is_absolute() else (base_dir / p)

    return Config(
        target=target,
        generators=generators,
        reviewer=reviewer,
        monitor=monitor,
        state_dir=resolve(data["state_dir"]),
        duration=duration,
        sessions_per_hour=float(data["sessions_per_hour"]),
        seed=data["seed"],
        canary_listener=listener,
        markers=list(data["markers"]),
        domains=list(data["domains"]),
        doc_words=int(data["doc_words"]),
        research_share=float(data["research_share"]),
        archive_share=float(data["archive_share"]),
        public_share=float(data["public_share"]),
        max_tasks=int(data["max_tasks"]),
        review_every=int(data["review_every"]),
        max_tokens=int(data["max_tokens"]),
        timeout=float(data["timeout"]),
        retries=int(data["retries"]),
        backoff=float(data["backoff"]),
        monitor_grace=float(data["monitor_grace"]),
        ab_delta_min_events=int(data["ab_delta_min_events"]),
        sources_file=resolve(data["sources_file"]),
    )


def load_config(path: str | Path | None, overrides: dict | None = None) -> Config:
    """Load canary.json (if given), apply dotted-key overrides such as 'target.model'."""
    raw: dict = {}
    base_dir = Path.cwd()
    if path:
        p = Path(path)
        if not p.exists():
            raise ConfigError(f"config file not found: {p} (run 'init' to create one)")
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{p}: invalid JSON: {exc}") from exc
        base_dir = p.resolve().parent
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        node = raw
        parts = key.split(".")
        for part in parts[:-1]:
            if not isinstance(node.get(part), dict):
                node[part] = {}
            node = node[part]
        node[parts[-1]] = value
    return build_config(raw, base_dir)


def sample_config() -> dict:
    sample = copy.deepcopy(DEFAULTS)
    sample["_comment"] = "Basalt exposes an OpenAI-compatible API on 8080; see README for every key."
    sample["target"]["model"] = ""
    sample["monitor"] = {"base_url": "http://127.0.0.1:8080", "api_key": ""}
    sample["_reviewer_example"] = {
        "kind": "openai", "base_url": "https://api.example.com", "api_key": "env:REVIEWER_API_KEY",
        "model": "reviewer-model", "extra_headers": {},
    }
    return sample


def same_endpoint(a: dict, b: dict) -> bool:
    def norm(s):
        return (s["base_url"].rstrip("/").lower(), (s.get("model") or "").strip().lower())

    return norm(a) == norm(b)
