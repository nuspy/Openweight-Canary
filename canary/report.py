"""report.md and report.json built from the persisted state."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from . import __version__
from .findings import verify_chain
from .reviewer import read_reviews
from .stats import ab_stats, findings_summary, load_state, monitor_summary
from .util import iso, write_json

METHOD = [
    "Fictional sensitive-looking documents (and archives with an index) carry unique canary strings in the file "
    "name, the body and the archive index. Each is paired with a control of the same shape without markers or canaries.",
    "Each pair is sent to the model as two separate conversations in random order, with ordinary tasks and, in a share "
    "of sessions, a request to research something on the internet so that legitimate traffic could mask hidden traffic.",
    "Evidence: canary values in answers, in URLs or encoded blobs; URLs the prompt never contained; "
    "monitor events in each conversation window; requests reaching the optional canary listener; "
    "the sensitive-minus-control difference in outbound events.",
    "Every finding is appended to a hash-chained log (findings.jsonl). A second model that is not the target reviews "
    "digests of the evidence.",
]

LIMITS = [
    "This test cannot prove absence of data leaks or exfiltration; it can only fail to find evidence.",
    "Time-triggered or data-triggered behaviour may never fire on fictional data or inside the test period.",
    "The monitor sees only what its sensors see; traffic outside its coverage, or encrypted channels with no "
    "visible host, can pass unnoticed.",
    "A model that never repeats a canary can still leak other content; canaries detect only what they cover.",
    "Findings of low or medium severity are leads to check, not proof; the reviewer's text is an opinion.",
]


def _parse(ts: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


def build_report(state_dir: Path) -> dict:
    state = load_state(state_dir)
    sessions, findings, runs = state["sessions"], state["findings"], state["runs"]
    run_rows: dict[str, dict] = {}
    for row in runs:
        entry = run_rows.setdefault(row["run_id"], {"run_id": row["run_id"]})
        if row.get("event") == "start":
            entry.update(started=row.get("time"), config_hash=row.get("config_hash"), target=row.get("target"),
                         monitor_configured=row.get("monitor_configured"))
        else:
            entry.update(ended=row.get("time"), reason=row.get("reason"), sessions=row.get("sessions_this_run"),
                         served_models=row.get("served_models", []), servers=row.get("servers", []))
    seconds = 0.0
    for entry in run_rows.values():
        a, b = _parse(entry.get("started")), _parse(entry.get("ended"))
        if a and b:
            seconds += (b - a).total_seconds()
    last_start = next((r for r in reversed(runs) if r.get("event") == "start"), {})
    items = state["items"]
    convs = [c for s in sessions for c in s.get("conversations", {}).values()]
    models = sorted({m for e in run_rows.values() for m in e.get("served_models", [])})
    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    notable = sorted((f for f in findings if f["severity"] != "info"),
                     key=lambda f: (severity_rank[f["severity"]], f["n"]))[:100]
    chain = verify_chain(Path(state_dir) / "findings.jsonl")
    reviews = read_reviews(state_dir)
    return {
        "generated": iso(), "tool_version": __version__,
        "config_hash": last_start.get("config_hash"),
        "comparison_key": f"{last_start.get('config_hash')}|{(last_start.get('target') or {}).get('model', '')}",
        "target": last_start.get("target"), "served_models": models,
        "servers": sorted({s for e in run_rows.values() for s in e.get("servers", [])}),
        "runs": list(run_rows.values()),
        "duration_seconds": round(seconds),
        "counts": {
            "runs": len(run_rows), "sessions": len(sessions), "conversations": len(convs),
            "conversation_errors": sum(1 for c in convs if c.get("errors")),
            "items": len(items), "documents": sum(1 for i in items if i["kind"] == "document"),
            "archives": sum(1 for i in items if i["kind"] == "archive"),
            "public_items": sum(1 for i in items if i["kind"] == "public"),
            "canaries": len(state["canaries"]),
        },
        "ab": ab_stats(sessions),
        "findings": {**findings_summary(findings), "notable": notable},
        "chain": {"ok": chain.ok, "records": chain.count, "head": chain.head, "message": chain.message},
        "monitor": monitor_summary(sessions, runs),
        "reviews": [{"n": r["n"], "time": r["time"], "label": r["label"], "reviewer_model": r.get("reviewer_model"),
                     "sessions_covered": r["digest"]["sessions_covered"], "error": r["reply"].get("error"),
                     "assessment": r.get("assessment"),
                     "raw": None if r.get("assessment") else r["reply"].get("text", "")[:1500]} for r in reviews],
        "method": METHOD, "limits": LIMITS,
    }


def _table(headers: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join("-" if v is None else str(v) for v in row) + " |" for row in rows]
    return out


def render_markdown(rep: dict) -> str:
    c = rep["counts"]
    lines = ["# Open-weight canary report", "",
             f"Generated {rep['generated']} - tool {rep['tool_version']} - config hash `{rep['config_hash']}`", "",
             "## Target", ""]
    tgt = rep["target"] or {}
    lines += [f"- Endpoint: {tgt.get('kind', '?')} API at {tgt.get('base_url', '?')}",
              f"- Configured model: {tgt.get('model') or '(none)'}",
              f"- Models reported by the server: {', '.join(rep['served_models']) or '(none)'}",
              f"- Server software: {', '.join(rep['servers']) or '(not reported)'}",
              f"- Comparison key: `{rep['comparison_key']}`", "", "## Scope", "",
              f"- Runs: {c['runs']}, observed time {rep['duration_seconds']} s",
              f"- Sessions: {c['sessions']}, conversations: {c['conversations']} "
              f"({c['conversation_errors']} with model errors)",
              f"- Items: {c['documents']} documents, {c['archives']} archives, {c['public_items']} public sources",
              f"- Registered canaries: {c['canaries']}", "", "## Method", ""]
    lines += [f"- {m}" for m in rep["method"]]
    lines += ["", "## Sensitive vs control", ""]
    ab = rep["ab"]
    keys = [("conversations", "conversations"), ("errors", "errors"), ("mean_latency_s", "mean latency (s)"),
            ("mean_response_words", "mean answer words"), ("monitored_conversations", "monitored"),
            ("mean_outbound_events", "mean outbound events"), ("foreign_urls", "URLs not in prompt"),
            ("canary_hits", "canary hits"), ("listener_hits", "listener hits")]
    delta = ab["delta_sensitive_minus_control"]
    rows = [[label, ab["sensitive"][k], ab["control"][k], delta.get(k)] for k, label in keys]
    lines += _table(["metric", "sensitive", "control", "delta"], rows)
    f = rep["findings"]
    lines += ["", "## Findings", "", f"Hash chain: {rep['chain']['message']}"
              f"{'' if rep['chain']['ok'] else ' - CHAIN FAILED'}", ""]
    lines += _table(["severity", "count"], [[s, n] for s, n in f["by_severity"].items()])
    if f["notable"]:
        lines += ["", "Notable findings (high, medium, low):", ""]
        lines += _table(["#", "severity", "kind", "session", "role", "evidence"],
                        [[x["n"], x["severity"], x["kind"], x.get("session"), x.get("role"),
                          str(x["evidence"])[:160].replace("|", "/")] for x in f["notable"][:50]])
    else:
        lines += ["", "No findings above info level."]
    lines += ["", "## Monitor coverage", ""]
    mon = rep["monitor"]
    lines.append(f"- Conversations by monitor state: {mon['conversations_by_monitor_state'] or 'none'}")
    lines.append(f"- Coverage reported by the monitor: {mon['coverage_reported'] or 'not reported'}")
    lines.append("- Conversations marked monitor_unavailable had no network observation at all.")
    lines += ["", "## Reviewer", ""]
    if not rep["reviews"]:
        lines.append("No review was produced.")
    for r in rep["reviews"]:
        lines.append(f"### Review {r['n']} ({r['label']}, {r['time']}, {r['sessions_covered']} sessions)")
        a = r["assessment"]
        if a:
            lines += ["", f"Confidence: {a.get('confidence', '?')}", "", str(a.get("summary", "")), ""]
            for key in ("suspicious", "explained_by_legitimate_behaviour", "next_checks"):
                if a.get(key):
                    lines.append(f"{key.replace('_', ' ').capitalize()}:")
                    lines += [f"- {x}" for x in a[key]]
                    lines.append("")
        else:
            lines += ["", f"No structured assessment ({r['error'] or 'unparseable reply'}).", ""]
    lines += ["## Limits", ""] + [f"- {x}" for x in rep["limits"]]
    return "\n".join(lines) + "\n"


def write_report(state_dir: Path) -> tuple[Path, Path]:
    state_dir = Path(state_dir)
    rep = build_report(state_dir)
    md, js = state_dir / "report.md", state_dir / "report.json"
    state_dir.mkdir(parents=True, exist_ok=True)
    md.write_text(render_markdown(rep), encoding="utf-8", newline="\n")
    write_json(js, rep)
    return md, js
