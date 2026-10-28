"""Hash-chained findings log (findings.jsonl)."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .util import canonical, iso, read_jsonl, sha256_hex

GENESIS = "0" * 64
SEVERITIES = ("high", "medium", "low", "info")


@dataclass
class VerifyResult:
    ok: bool
    count: int
    head: str
    message: str


def record_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return sha256_hex(record["prev"] + canonical(body))


class FindingsLog:
    def __init__(self, path: Path, run_id: str = ""):
        self.path = Path(path)
        self.run_id = run_id
        self._lock = threading.Lock()
        self.harness: str | None = None
        self._count = 0
        self._prev = GENESIS
        for rec in read_jsonl(self.path):
            self._count += 1
            self._prev = rec.get("hash", self._prev)

    def append(self, severity: str, kind: str, evidence: dict, session: int | None = None,
               role: str | None = None, harness: str | None = None) -> dict:
        if severity not in SEVERITIES:
            raise ValueError(f"bad severity {severity!r}")
        with self._lock:
            record = {
                "n": self._count + 1, "ts": time.time(), "time": iso(), "run": self.run_id,
                "severity": severity, "kind": kind, "session": session, "role": role,
                "evidence": evidence, "prev": self._prev,
            }
            harness = harness or self.harness
            if harness:
                record["harness"] = harness
            record["hash"] = record_hash(record)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._count += 1
            self._prev = record["hash"]
            return record


def read_findings(path: Path) -> list[dict]:
    return read_jsonl(path)


def verify_chain(path: Path) -> VerifyResult:
    path = Path(path)
    if not path.exists():
        return VerifyResult(True, 0, GENESIS, "no findings file")
    prev = GENESIS
    count = 0
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, count, prev, f"line {lineno}: not valid JSON")
            if rec.get("prev") != prev:
                return VerifyResult(False, count, prev, f"line {lineno}: chain broken (prev mismatch)")
            if rec.get("hash") != record_hash(rec):
                return VerifyResult(False, count, prev, f"line {lineno}: record altered (hash mismatch)")
            prev = rec["hash"]
            count += 1
    return VerifyResult(True, count, prev, f"{count} records, chain intact")
