"""Telling a person: a finding that matters is written where it cannot be missed, and an optional command is run.

A long test finds many weak things (a tool used that nobody asked for) and few that matter. Everything goes to findings.jsonl; what
matters goes to `state/ALERTS.md` too, with the place of the transcript to read, and `state/ALERT` is created so that anything that
watches a folder can tell. `alerts.command` in the config is run for each alert with CANARY_ALERT_* in its environment (a notification,
a message, an e-mail: the person chooses). Nothing here decides that a model is guilty."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
from pathlib import Path

from .util import iso

log = logging.getLogger("canary")
RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
# kinds that are alerts whatever their severity: they say that the sensitive twin was treated differently
ALWAYS = {"harness_call_asymmetry", "harness_trigger_ab", "tool_egress_sequence", "narrative_trigger_reaction"}


class Alerts:
    def __init__(self, state_dir: Path, spec: dict | None = None):
        self.state = Path(state_dir)
        spec = spec or {}
        self.min_rank = RANK.get(spec.get("min_severity", "high"), 0)
        self.command = spec.get("command") or ""
        self._lock = threading.Lock()
        self.count = 0

    def wanted(self, record: dict) -> bool:
        return RANK.get(record["severity"], 9) <= self.min_rank or record["kind"] in ALWAYS

    def handle(self, record: dict) -> None:
        if not self.wanted(record):
            return
        session, role, harness = record.get("session"), record.get("role") or "", record.get("harness") or ""
        name = f"s{int(session):05d}_{role}{('_' + harness) if harness else ''}.json" if session and role else ""
        where = f"conversations/{name}" if name else "sessions.jsonl"
        evidence = json.dumps(record.get("evidence"), ensure_ascii=False)[:600]
        block = (f"## {record['time']}  {record['severity'].upper()}  {record['kind']}\n"
                 f"- finding n={record['n']}, session {session}, role {role or '-'}, profile {harness or '-'}\n"
                 f"- read: {where}\n- evidence: {evidence}\n\n")
        with self._lock:
            self.count += 1
            self.state.mkdir(parents=True, exist_ok=True)
            with (self.state / "ALERTS.md").open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(block)
            (self.state / "ALERT").write_text(f"{self.count} alert(s) in this run, last at {iso()}; read ALERTS.md\n", encoding="utf-8")
        log.warning("ALERT %s %s (session %s): see %s", record["severity"], record["kind"], session, self.state / "ALERTS.md")
        if self.command:
            env = {**os.environ, "CANARY_ALERT_KIND": record["kind"], "CANARY_ALERT_SEVERITY": record["severity"],
                   "CANARY_ALERT_SESSION": str(session or ""), "CANARY_ALERT_FILE": str(self.state / "ALERTS.md")}
            try:
                subprocess.Popen(self.command, shell=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as exc:
                log.warning("alert command failed to start: %s", exc)
