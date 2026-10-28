"""Ready-made configs for a runtime/model pair, and the text of `python -m canary presets`."""
from __future__ import annotations

from .config import sample_config
from .vendors import Catalog

EXTERNAL_MONITOR_RUNTIMES = {"basalt"}


def build_config(catalog: Catalog, runtime_id: str, model: str = "", vendor_id: str | None = None,
                 base_url: str | None = None) -> dict:
    """A canary.json for the runtime. Basalt keeps its own netwatch as the monitor; every other runtime gets the
    built-in connection sampler watching that runtime's process names."""
    runtime = catalog.runtime(runtime_id)
    cfg = sample_config()
    cfg["_comment"] = (f"Generated for {runtime['name']}. {runtime.get('notes', '')} "
                       "See README.md for every key.").strip()
    cfg["target"]["kind"] = runtime.get("kind", "openai")
    cfg["target"]["base_url"] = base_url or runtime["default_base_url"]
    cfg["target"]["model"] = model or ""
    cfg["runtime"] = runtime["id"]
    vendor = catalog.vendors.get(vendor_id) if vendor_id else catalog.detect_vendor(model)
    if vendor_id and vendor is None:
        raise ValueError(f"unknown vendor {vendor_id!r}; run 'python -m canary presets'")
    cfg["vendor"] = vendor["id"] if vendor else None
    if runtime["id"] in EXTERNAL_MONITOR_RUNTIMES and runtime.get("monitor_base_url"):
        cfg["monitor"] = {"base_url": runtime["monitor_base_url"], "api_key": ""}
        cfg["network_watch"] = None
    else:
        cfg["monitor"] = None
        cfg["network_watch"] = {"mode": "builtin", "interval": 1.0, "resolve": True,
                                "process_names": list(runtime.get("process_names", [])),
                                "cmdline_hints": list(runtime.get("cmdline_hints", [])), "pids": []}
    return cfg


def describe(catalog: Catalog) -> str:
    lines = ["Runtimes (use with: init --runtime <id>)"]
    for rt in catalog.runtimes.values():
        mon = "own monitor (netwatch API)" if rt["id"] in EXTERNAL_MONITOR_RUNTIMES else "built-in sampler"
        lines.append(f"  {rt['id']:<10} {rt['default_base_url']:<26} {rt['kind']:<10} {mon}")
    lines.append("")
    lines.append("Vendors (detected from the model name; override with --vendor <id>)")
    for v in catalog.vendors.values():
        lines.append(f"  {v['id']:<16} {v['name']:<26} HF: {', '.join(v.get('hf_orgs', [])) or '-'}")
    lines.append("")
    lines.append("Hosted inference services also flagged: " + ", ".join(catalog.hosted_apis))
    lines.append("Model hubs (info only): " + ", ".join(catalog.hubs))
    return "\n".join(lines)
