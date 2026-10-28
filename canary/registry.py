"""Canary registry (canaries.jsonl) and the matcher built from it."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path

from .util import append_jsonl, read_jsonl

MIN_FRAGMENT = 8


@dataclass
class Canary:
    canary_id: str
    doc_id: str
    kind: str
    value: str
    fragments: list[str] = field(default_factory=list)

    def needles(self) -> list[str]:
        out = [self.value] + [f for f in self.fragments if len(f) >= MIN_FRAGMENT]
        return [n.lower() for n in out]

    def to_row(self) -> dict:
        return {"id": self.canary_id, "doc": self.doc_id, "kind": self.kind,
                "value": self.value, "fragments": self.fragments}

    @classmethod
    def from_row(cls, row: dict) -> "Canary":
        return cls(row["id"], row["doc"], row["kind"], row["value"], row.get("fragments", []))


@dataclass
class Hit:
    canary: Canary
    matched: str


class Matcher:
    def __init__(self, canaries: list[Canary]):
        self.canaries = canaries
        self._needles = [(c, n) for c in canaries for n in c.needles()]

    def find(self, text: str) -> list[Hit]:
        low = text.lower()
        hits: dict[str, Hit] = {}
        for canary, needle in self._needles:
            if canary.canary_id not in hits and needle in low:
                hits[canary.canary_id] = Hit(canary, needle)
        return list(hits.values())


class Registry:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._items: list[Canary] = [Canary.from_row(r) for r in read_jsonl(self.path)]
        self._matcher: Matcher | None = None

    def __len__(self) -> int:
        return len(self._items)

    def all(self) -> list[Canary]:
        return list(self._items)

    def values(self) -> set[str]:
        return {c.value for c in self._items}

    def add(self, canaries: list[Canary]) -> None:
        with self._lock:
            for c in canaries:
                self._items.append(c)
                append_jsonl(self.path, c.to_row())
            self._matcher = None

    def matcher(self) -> Matcher:
        with self._lock:
            if self._matcher is None:
                self._matcher = Matcher(list(self._items))
            return self._matcher
