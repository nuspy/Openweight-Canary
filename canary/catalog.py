"""The editable catalogs: simulated people (personas), the prominent figures of the fake workspaces, and the contexts (document banks).

The shipped defaults are in canary/data/catalog.json (people) and canary/scenarios.py (contexts). The person running the test keeps changes in one
file (`personas.file` of the config, `personas.local.json` by default): new rows, rows that replace a default with the same id, and a list of
default ids that are removed. Nothing in a default file is ever rewritten, so a default can always be reset."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from . import scenarios
from .generator import BANKS
from .util import write_json

KINDS = ("personas", "figures", "contexts")
DATA = Path(__file__).with_name("data") / "catalog.json"
BANK_LISTS = ("actors", "assets", "places", "topics", "verbs", "past", "types")
CONTEXT_META = {
    "taiwan_diplomacy": {"label": "Diplomacy about Taiwan", "categories": ["diplomat", "politician"]},
    "taiwan_military": {"label": "Military affairs about Taiwan", "categories": ["general", "politician"]},
    "cyber_russia_europe": {"label": "Cyber campaigns of Russia against Europe", "categories": ["intelligence", "general", "politician"]},
    "cyber_china_us": {"label": "Cyber campaigns of China against the United States", "categories": ["intelligence", "industrialist", "tech_ceo"]},
}


class CatalogError(ValueError):
    pass


def _defaults() -> dict[str, list[dict]]:
    base = json.loads(DATA.read_text(encoding="utf-8"))
    contexts = []
    for cid, bank in scenarios.SCENARIO_BANKS.items():
        meta = CONTEXT_META[cid]
        contexts.append({"id": cid, "label": meta["label"], "categories": list(meta["categories"]), "sides": list(scenarios.SIDES_OF[cid]),
                         **{k: list(bank[k]) for k in BANK_LISTS}, "office": bank["office"]})
    return {"personas": base["personas"], "figures": base["figures"], "contexts": contexts}


def _read(path: str | Path | None) -> dict:
    empty = {"personas": [], "figures": [], "contexts": [], "removed": {k: [] for k in KINDS}}
    if not path or not Path(path).is_file():
        return empty
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for kind in KINDS:
        empty[kind] = [r for r in data.get(kind, []) if isinstance(r, dict) and r.get("id")] if isinstance(data.get(kind), list) else []
        empty["removed"][kind] = list((data.get("removed") or {}).get(kind, []))
    for row in empty["personas"]:
        row.setdefault("real", True)
    return empty


def effective(path: str | Path | None, register: bool = True) -> dict[str, list[dict]]:
    """Defaults, minus the removed ones, with replacements, plus the new rows; each row says if it is a default (`builtin`) and if it was changed."""
    base, mine = _defaults(), _read(path)
    out: dict[str, list[dict]] = {}
    for kind in KINDS:
        replaced = {r["id"]: r for r in mine[kind]}
        rows = []
        for d in base[kind]:
            if d["id"] in mine["removed"][kind]:
                continue
            row = replaced.pop(d["id"], None)
            rows.append({**(row or d), "builtin": True, "edited": row is not None})
        rows += [{**r, "builtin": False, "edited": False} for r in replaced.values()]
        out[kind] = rows
    if register:
        for ctx in out["contexts"]:
            BANKS[ctx["id"]] = {**{k: list(ctx[k]) for k in BANK_LISTS}, "office": ctx["office"]}
    return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "row"


def _text(row: dict, key: str, required: bool = True) -> str:
    v = str(row.get(key) or "").strip()
    if required and not v:
        raise CatalogError(f"{key} is required")
    return v


def validate(kind: str, row: dict) -> dict:
    """The row cleaned up, or a CatalogError saying what is wrong."""
    from .personas import CATEGORIES
    if kind == "personas":
        cat = _text(row, "category")
        if cat not in CATEGORIES:
            raise CatalogError(f"category: one of {', '.join(sorted(CATEGORIES))}")
        return {"category": cat, "name": _text(row, "name", False), "role": _text(row, "role"), "org": _text(row, "org"), "real": bool(row.get("real", True))}
    if kind == "figures":
        side = _text(row, "side")
        if side not in scenarios.SIDES:
            raise CatalogError(f"side: one of {', '.join(scenarios.SIDES)}")
        return {"side": side, "name": _text(row, "name"), "role": _text(row, "role", False), "org": _text(row, "org", False)}
    if kind == "contexts":
        out = {"label": _text(row, "label"), "office": _text(row, "office")[:12] or "DOC"}
        for key in BANK_LISTS:
            raw = row.get(key)
            items = [s.strip() for s in (raw.splitlines() if isinstance(raw, str) else raw or []) if str(s).strip()]
            if len(items) < 2:
                raise CatalogError(f"{key}: at least two entries")
            out[key] = items
        out["categories"] = [c for c in row.get("categories") or [] if c in CATEGORIES]
        out["sides"] = [s for s in row.get("sides") or [] if s in scenarios.SIDES] or list(scenarios.DEFAULT_SIDES)
        return out
    raise CatalogError(f"unknown catalog {kind}")


def upsert(path: str | Path, kind: str, row: dict) -> dict:
    """Create a row (no id) or replace the one with that id; a default is replaced by a row of the same id."""
    if kind not in KINDS:
        raise CatalogError(f"unknown catalog {kind}")
    clean = validate(kind, row)
    mine = _read(path)
    rid = str(row.get("id") or "").strip()
    known = {r["id"] for r in effective(path, register=False)[kind]}
    if not rid:
        base = _slug(clean.get("name") or clean.get("label") or clean.get("org") or kind)
        rid, n = base, 2
        while rid in known:
            rid, n = f"{base}-{n}", n + 1
    elif rid not in known and rid.startswith("..."):
        raise CatalogError("bad id")
    mine[kind] = [r for r in mine[kind] if r["id"] != rid] + [{"id": rid, **clean}]
    mine["removed"][kind] = [i for i in mine["removed"][kind] if i != rid]
    _write(path, mine)
    return {"id": rid, **clean}


def delete(path: str | Path, kind: str, rid: str) -> None:
    """Remove a row of the file; a default is only listed as removed."""
    if kind not in KINDS:
        raise CatalogError(f"unknown catalog {kind}")
    mine = _read(path)
    if rid not in {r["id"] for r in effective(path, register=False)[kind]}:
        raise CatalogError("no such row")
    mine[kind] = [r for r in mine[kind] if r["id"] != rid]
    if rid in {r["id"] for r in _defaults()[kind]} and rid not in mine["removed"][kind]:
        mine["removed"][kind].append(rid)
    _write(path, mine)


def reset(path: str | Path, kind: str, rid: str | None = None) -> None:
    """Undo changes to one default (or to every default of that kind): the replacement and the removal go away."""
    mine = _read(path)
    defaults = {r["id"] for r in _defaults()[kind]}
    mine[kind] = [r for r in mine[kind] if r["id"] not in defaults or (rid and r["id"] != rid)]
    mine["removed"][kind] = [i for i in mine["removed"][kind] if rid and i != rid]
    _write(path, mine)


def _write(path: str | Path, mine: dict) -> None:
    out = {"_comment": "Your changes to the catalogs of the canary. Not tracked by git; see docs/catalog.md.",
           **{k: mine[k] for k in KINDS}, "removed": mine["removed"]}
    write_json(Path(path), copy.deepcopy(out))
