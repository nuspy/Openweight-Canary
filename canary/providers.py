"""Client for OpenAI-compatible and Anthropic-compatible chat APIs. Never raises on API failure."""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from .util import opener_for

log = logging.getLogger("canary")

ANTHROPIC_VERSION = "2023-06-01"


@dataclass
class Reply:
    text: str = ""
    error: str | None = None
    latency: float = 0.0
    tokens_in: int | None = None
    tokens_out: int | None = None
    status: int | None = None
    served_model: str | None = None
    server: str | None = None
    attempts: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


def _flatten_content(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(part.get("text") or "")
            elif isinstance(part, str):
                parts.append(part)
        return "".join(parts)
    return ""


class Provider:
    def __init__(self, spec: dict, *, timeout: float = 600, retries: int = 3,
                 backoff: float = 2.0, sleep=time.sleep):
        self.spec = spec
        self.kind = spec["kind"]
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.sleep = sleep

    @property
    def url(self) -> str:
        base = self.spec["base_url"].rstrip("/")
        tail = "/chat/completions" if self.kind == "openai" else "/messages"
        return base + tail if base.endswith("/v1") else base + "/v1" + tail

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "openweight-canary/0.1"}
        key = self.spec.get("api_key")
        if key:
            headers["Authorization"] = f"Bearer {key}"
            if self.kind == "anthropic":
                headers["x-api-key"] = key
        if self.kind == "anthropic":
            headers["anthropic-version"] = ANTHROPIC_VERSION
        headers.update(self.spec.get("extra_headers") or {})
        return headers

    def _body(self, messages: list[dict], system: str | None, max_tokens: int) -> bytes:
        body: dict = {"messages": messages, "max_tokens": max_tokens}
        if self.spec.get("model"):
            body["model"] = self.spec["model"]
        if self.kind == "openai":
            body["stream"] = False
            if system:
                body["messages"] = [{"role": "system", "content": system}] + messages
        elif system:
            body["system"] = system
        return json.dumps(body).encode("utf-8")

    def _parse(self, raw: bytes, reply: Reply) -> None:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        reply.served_model = data.get("model")
        usage = data.get("usage") or {}
        if self.kind == "openai":
            choices = data.get("choices") or []
            if not choices:
                raise ValueError("no choices in response")
            reply.text = _flatten_content((choices[0].get("message") or {}).get("content"))
            reply.tokens_in = usage.get("prompt_tokens")
            reply.tokens_out = usage.get("completion_tokens")
        else:
            reply.text = _flatten_content(data.get("content"))
            reply.tokens_in = usage.get("input_tokens")
            reply.tokens_out = usage.get("output_tokens")

    def chat(self, messages: list[dict], system: str | None = None, max_tokens: int = 1024) -> Reply:
        body = self._body(messages, system, max_tokens)
        reply = Reply()
        started = time.monotonic()
        for attempt in range(self.retries + 1):
            reply.attempts = attempt + 1
            retryable = True
            try:
                req = urllib.request.Request(self.url, data=body, headers=self._headers(), method="POST")
                with opener_for(self.url).open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    reply.status = resp.status
                    reply.server = resp.headers.get("Server")
                self._parse(raw, reply)
                reply.error = None
                break
            except urllib.error.HTTPError as exc:
                reply.status = exc.code
                detail = exc.read()[:300].decode("utf-8", errors="replace")
                reply.error = f"HTTP {exc.code}: {detail}"
                retryable = exc.code in (408, 425, 429) or exc.code >= 500
            except (ValueError, KeyError, TypeError) as exc:
                reply.error = f"bad response: {exc}"
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                reply.error = f"connection: {exc}"
            if not retryable or attempt == self.retries:
                break
            delay = min(self.backoff * (2 ** attempt), 60.0)
            log.warning("request failed (%s); retry %d/%d in %.1fs", reply.error, attempt + 1, self.retries, delay)
            self.sleep(delay)
        reply.latency = time.monotonic() - started
        return reply
