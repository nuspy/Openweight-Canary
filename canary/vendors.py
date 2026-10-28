"""Reference data about open-weight vendors, hubs and serving runtimes (vendors.json + vendors.local.json)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .util import LOOPBACK_HOSTS

BUILTIN_PATH = Path(__file__).with_name("vendors.json")
LOCAL_NAME = "vendors.local.json"
SECTIONS = ("vendors", "hubs", "hosted_apis", "runtimes")


class VendorsError(ValueError):
    pass


@dataclass(frozen=True)
class HostMatch:
    """One classification of a destination host."""
    tag: str          # e.g. vendor_domain:qwen
    severity: str     # medium | info
    name: str
    detail: str = ""


def _read(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise VendorsError(f"{path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise VendorsError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise VendorsError(f"{path}: top level must be an object")
    return data


def merge(base: dict, local: dict) -> dict:
    """Merge a user file over the built-in data.

    An entry with an existing id replaces the fields it names; {"id": "x", "remove": true} deletes the entry;
    a new id is appended. "allow_domains" lists hosts that are never flagged.
    """
    merged = {k: [dict(e) for e in base.get(k, [])] for k in SECTIONS}
    merged["hf_library_calls"] = dict(base.get("hf_library_calls", {}))
    merged["allow_domains"] = [str(d).lower() for d in base.get("allow_domains", [])]
    for section in SECTIONS:
        index = {e["id"]: e for e in merged[section]}
        for entry in local.get(section, []) or []:
            if not isinstance(entry, dict) or not entry.get("id"):
                raise VendorsError(f"{section}: every entry needs an id")
            if entry.get("remove"):
                index.pop(entry["id"], None)
            elif entry["id"] in index:
                index[entry["id"]].update({k: v for k, v in entry.items() if k != "remove"})
            else:
                index[entry["id"]] = {k: v for k, v in entry.items() if k != "remove"}
        merged[section] = list(index.values())
    merged["allow_domains"] += [str(d).lower() for d in local.get("allow_domains", []) or []]
    return merged


def domain_matches(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().strip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


class Catalog:
    def __init__(self, data: dict):
        self.data = data
        self.vendors = {v["id"]: v for v in data["vendors"]}
        self.hubs = {h["id"]: h for h in data["hubs"]}
        self.hosted_apis = {h["id"]: h for h in data["hosted_apis"]}
        self.runtimes = {r["id"]: r for r in data["runtimes"]}
        self.allow = list(data.get("allow_domains", []))
        self._patterns = []
        for vendor in self.vendors.values():
            for pat in vendor.get("model_name_patterns", []):
                try:
                    self._patterns.append((re.compile(pat, re.IGNORECASE), vendor["id"]))
                except re.error as exc:
                    raise VendorsError(f"vendor {vendor['id']}: bad model_name_pattern {pat!r}: {exc}") from exc

    # -- lookups -------------------------------------------------------------------------

    def runtime(self, runtime_id: str) -> dict:
        key = (runtime_id or "").lower()
        aliases = {"llamacpp": "llama.cpp", "llama-cpp": "llama.cpp", "llama_cpp": "llama.cpp",
                   "llama-server": "llama.cpp", "lm-studio": "lmstudio", "lm_studio": "lmstudio",
                   "mlx": "mlx-lm", "mlx_lm": "mlx-lm", "tensorrt-llm": "trtllm", "trtllm-serve": "trtllm"}
        key = aliases.get(key, key)
        if key not in self.runtimes:
            raise VendorsError(f"unknown runtime {runtime_id!r}; known: {', '.join(sorted(self.runtimes))}")
        return self.runtimes[key]

    def detect_vendor(self, model_name: str) -> dict | None:
        """The vendor whose model_name_patterns match the model name, or None. First match in file order wins,
        except that a longer matched text wins over a shorter one (so 'qwen3-nemotron' picks the more specific)."""
        name = (model_name or "").strip()
        if not name:
            return None
        best = None
        for pattern, vendor_id in self._patterns:
            m = pattern.search(name)
            if m and (best is None or len(m.group(0)) > best[0]):
                best = (len(m.group(0)), vendor_id)
        return self.vendors[best[1]] if best else None

    def vendor_for_org(self, org: str) -> dict | None:
        for vendor in self.vendors.values():
            if org in vendor.get("hf_orgs", []):
                return vendor
        return None

    # -- host classification ---------------------------------------------------------------

    def classify_host(self, host: str, own_hosts=(), runtime_id: str | None = None) -> list[HostMatch]:
        """Tags for a destination host. Hosts that belong to the model's own configured server, loopback and
        user-allowed domains are never classified. Nothing here implies bad intent: a match means the host is
        one a local model has no obvious reason to contact."""
        host = (host or "").split(":")[0].strip("[]").lower().rstrip(".")
        if not host or host in LOOPBACK_HOSTS or host in {h.lower() for h in own_hosts if h}:
            return []
        if any(domain_matches(host, d) for d in self.allow):
            return []
        out: list[HostMatch] = []
        for vendor in self.vendors.values():
            if any(domain_matches(host, d) for d in vendor.get("vendor_domains", [])):
                out.append(HostMatch(f"vendor_domain:{vendor['id']}", "medium", vendor["name"],
                                     "domain belongs to this vendor's own sites or cloud API"))
        for api in self.hosted_apis.values():
            if any(domain_matches(host, d) for d in api.get("domains", [])):
                out.append(HostMatch(f"hosted_api:{api['id']}", "medium", api["name"],
                                     "hosted inference or aggregation service"))
        for hub in self.hubs.values():
            if any(domain_matches(host, d) for d in hub.get("domains", [])):
                out.append(HostMatch(f"hub_domain:{hub['id']}", "info", hub["name"], hub.get("note", "")))
        runtimes = [self.runtime(runtime_id)] if runtime_id else []
        for rt in runtimes:
            for call in rt.get("known_calls", []):
                target = call.get("host", "")
                if target and target != "*" and domain_matches(host, target):
                    out.append(HostMatch(f"known_runtime_call:{rt['id']}", "info", rt["name"], call.get("when", "")))
                    break
        return out


def load_catalog(local_path: str | Path | None = None) -> Catalog:
    """Built-in data merged with an optional user file (default: ./vendors.local.json when present)."""
    data = _read(BUILTIN_PATH)
    path = Path(local_path) if local_path else Path(LOCAL_NAME)
    if path.exists():
        data = merge(data, _read(path))
    else:
        data = merge(data, {})
    return Catalog(data)
