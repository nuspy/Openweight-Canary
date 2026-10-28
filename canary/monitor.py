"""Client for the Basalt Security monitor (netwatch) API."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import quote

from .util import host_of, opener_for


class Monitor:
    def __init__(self, spec: dict, timeout: float = 10):
        self.base = spec["base_url"].rstrip("/")
        self.api_key = spec.get("api_key", "")
        self.timeout = timeout

    def _get(self, path: str):
        headers = {"Accept": "application/json", "User-Agent": "openweight-canary/0.1"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.base + path, headers=headers)
        with opener_for(self.base).open(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def status(self) -> dict | None:
        """The monitor status object (it may carry a 'coverage' field), or None when unreachable."""
        try:
            data = self._get("/api/netwatch/status")
        except (urllib.error.URLError, OSError, ValueError):
            return None
        return data if isinstance(data, dict) else {"raw": data}

    def events(self, since: float) -> list[dict] | None:
        """Events since a unix timestamp, or None when the API is unavailable."""
        try:
            data = self._get(f"/api/netwatch/events?since={quote(str(since))}&only=all")
        except (urllib.error.URLError, OSError, ValueError):
            return None
        if isinstance(data, dict):
            data = data.get("events", data.get("items"))
        if not isinstance(data, list):
            return None
        return [e for e in data if isinstance(e, dict)]


def event_time(event: dict) -> float | None:
    for key in ("ts", "time", "timestamp", "t"):
        value = event.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return None


def event_host(event: dict) -> str:
    for key in ("host", "hostname", "remote_host", "sni", "domain"):
        if event.get(key):
            return str(event[key]).lower()
    for key in ("url", "remote", "dest", "dst", "address"):
        value = event.get(key)
        if value:
            value = str(value)
            return host_of(value) or value.rsplit(":", 1)[0].strip("[]").lower()
    return ""
