"""Client for OpenAI-compatible and Anthropic-compatible chat APIs. Never raises on API failure."""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

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
    tool_calls: list = field(default_factory=list)
    message: dict | None = None

    def to_dict(self) -> dict:
        out = asdict(self)
        for key in ("tool_calls", "message"):
            if not out[key]:
                del out[key]
        return out


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


def _args_dict(raw) -> dict:
    """Tool-call arguments as a dict; unparseable text is kept under `_raw`."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            value = json.loads(raw)
        except ValueError:
            return {"_raw": raw}
        return value if isinstance(value, dict) else {"_value": value}
    return {}


def to_anthropic_messages(messages: list[dict]) -> list[dict]:
    """Convert OpenAI-style tool messages (assistant tool_calls, role tool) to Anthropic content blocks."""
    out: list[dict] = []
    for msg in messages:
        role = msg.get("role")
        if role == "assistant" and msg.get("tool_calls"):
            blocks = []
            if msg.get("content"):
                blocks.append({"type": "text", "text": msg["content"]})
            for call in msg["tool_calls"]:
                fn = call.get("function") or {}
                blocks.append({"type": "tool_use", "id": call.get("id"), "name": fn.get("name"),
                               "input": _args_dict(fn.get("arguments"))})
            out.append({"role": "assistant", "content": blocks})
        elif role == "tool":
            block = {"type": "tool_result", "tool_use_id": msg.get("tool_call_id"),
                     "content": msg.get("content") or ""}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        else:
            out.append({"role": role, "content": msg.get("content") or ""})
    return out


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

    def _body(self, messages: list[dict], system: str | None, max_tokens: int,
              tools: list[dict] | None = None) -> bytes:
        body: dict = {"messages": messages, "max_tokens": max_tokens}
        if self.spec.get("model"):
            body["model"] = self.spec["model"]
        if self.kind == "openai":
            body["stream"] = False
            if system:
                body["messages"] = [{"role": "system", "content": system}] + messages
            if tools:
                body["tools"] = tools
                body["tool_choice"] = "auto"
        else:
            if tools:
                body["messages"] = to_anthropic_messages(messages)
                body["tools"] = [{"name": t["function"]["name"], "description": t["function"].get("description", ""),
                                  "input_schema": t["function"].get("parameters") or {"type": "object"}}
                                 for t in tools]
            if system:
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
            message = choices[0].get("message") or {}
            reply.text = _flatten_content(message.get("content"))
            calls = []
            for i, call in enumerate(message.get("tool_calls") or []):
                fn = call.get("function") or {}
                calls.append({"id": call.get("id") or f"call_{i}", "name": fn.get("name") or "",
                              "arguments": _args_dict(fn.get("arguments"))})
            reply.tool_calls = calls
            if calls:
                reply.message = {"role": "assistant", "content": reply.text or None,
                                 "tool_calls": [{"id": c["id"], "type": "function",
                                                 "function": {"name": c["name"],
                                                              "arguments": json.dumps(c["arguments"])}}
                                                for c in calls]}
            reply.tokens_in = usage.get("prompt_tokens")
            reply.tokens_out = usage.get("completion_tokens")
        else:
            blocks = data.get("content")
            reply.text = _flatten_content(blocks)
            calls = []
            for i, block in enumerate(blocks if isinstance(blocks, list) else []):
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    calls.append({"id": block.get("id") or f"call_{i}", "name": block.get("name") or "",
                                  "arguments": _args_dict(block.get("input"))})
            reply.tool_calls = calls
            if calls:
                reply.message = {"role": "assistant", "content": reply.text or None,
                                 "tool_calls": [{"id": c["id"], "type": "function",
                                                 "function": {"name": c["name"],
                                                              "arguments": json.dumps(c["arguments"])}}
                                                for c in calls]}
            reply.tokens_in = usage.get("input_tokens")
            reply.tokens_out = usage.get("output_tokens")

    def chat(self, messages: list[dict], system: str | None = None, max_tokens: int = 1024,
             tools: list[dict] | None = None) -> Reply:
        body = self._body(messages, system, max_tokens, tools)
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
