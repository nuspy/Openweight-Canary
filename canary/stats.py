"""Aggregation of persisted state for the reviewer digest, status and report."""
from __future__ import annotations

from pathlib import Path

from .findings import SEVERITIES, read_findings
from .util import read_json, read_jsonl

ROLES = ("sensitive", "control")


def load_state(state_dir: Path) -> dict:
    state_dir = Path(state_dir)
    return {
        "sessions": read_jsonl(state_dir / "sessions.jsonl"),
        "findings": read_findings(state_dir / "findings.jsonl"),
        "runs": read_jsonl(state_dir / "runs.jsonl"),
        "canaries": read_jsonl(state_dir / "canaries.jsonl"),
        "items": read_jsonl(state_dir / "materials" / "items.jsonl"),
        "running": read_json(state_dir / "running.json", None),
    }


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 3) if values else None


def ab_stats(sessions: list[dict]) -> dict:
    """Per-role aggregates over all sessions plus the sensitive-minus-control delta."""
    out: dict = {}
    for role in ROLES:
        convs = [s["conversations"][role] for s in sessions if role in s.get("conversations", {})]
        outbound = [c["outbound_events"] for c in convs if c.get("outbound_events") is not None]
        out[role] = {
            "conversations": len(convs),
            "errors": sum(1 for c in convs if c.get("errors")),
            "mean_latency_s": _mean([c["latency"] for c in convs if c.get("latency") is not None]),
            "mean_tokens_out": _mean([c["tokens_out"] for c in convs if c.get("tokens_out") is not None]),
            "mean_response_words": _mean([c["response_words"] for c in convs if "response_words" in c]),
            "monitored_conversations": len(outbound),
            "outbound_events_total": sum(outbound),
            "mean_outbound_events": _mean(outbound),
            "foreign_urls": sum(c.get("foreign_urls", 0) for c in convs),
            "canary_hits": sum(c.get("canary_hits", 0) for c in convs),
            "listener_hits": sum(c.get("listener_hits", 0) for c in convs),
        }
    delta = {}
    for key in ("mean_latency_s", "mean_outbound_events", "foreign_urls", "canary_hits", "listener_hits"):
        a, b = out["sensitive"][key], out["control"][key]
        delta[key] = round(a - b, 3) if a is not None and b is not None else None
    out["delta_sensitive_minus_control"] = delta
    return out


def findings_summary(findings: list[dict]) -> dict:
    by_sev = {sev: 0 for sev in SEVERITIES}
    by_kind: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        key = f"{f.get('severity')}:{f.get('kind')}"
        by_kind[key] = by_kind.get(key, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_kind": dict(sorted(by_kind.items()))}


def _trim(value, limit: int = 200):
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "..."
    if isinstance(value, dict):
        return {k: _trim(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_trim(v, limit) for v in value[:10]]
    return value


def monitor_summary(sessions: list[dict], runs: list[dict]) -> dict:
    statuses: dict[str, int] = {}
    for s in sessions:
        for conv in s.get("conversations", {}).values():
            key = conv.get("monitor", "off")
            statuses[key] = statuses.get(key, 0) + 1
    coverage = [r["monitor_status"]["coverage"] for r in runs
                if isinstance(r.get("monitor_status"), dict) and "coverage" in r["monitor_status"]]
    return {"conversations_by_monitor_state": statuses, "coverage_reported": coverage[-1] if coverage else None}


def digest(state: dict, since_session: int = 0, max_findings: int = 40) -> dict:
    """Compact input for the reviewer: counts, A/B statistics and trimmed findings."""
    sessions = [s for s in state["sessions"] if s.get("session", 0) > since_session]
    findings = [f for f in state["findings"] if (f.get("session") or 0) > since_session or f.get("session") is None]
    order = {sev: i for i, sev in enumerate(SEVERITIES)}
    ranked = sorted(findings, key=lambda f: (order.get(f.get("severity"), 9), f.get("n", 0)))
    listed = [{"n": f["n"], "severity": f["severity"], "kind": f["kind"], "session": f.get("session"),
               "role": f.get("role"), "evidence": _trim(f.get("evidence", {}))}
              for f in ranked if f.get("severity") != "info"][:max_findings]
    return {
        "sessions_covered": len(sessions),
        "first_session": sessions[0]["session"] if sessions else None,
        "last_session": sessions[-1]["session"] if sessions else None,
        "findings": findings_summary(findings),
        "findings_listed": listed,
        "ab": ab_stats(sessions),
        "monitor": monitor_summary(sessions, state["runs"]),
        "registered_canaries": len(state["canaries"]),
    }
