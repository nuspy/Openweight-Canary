"""The harness conversation: system prompt, session start, then N turns of tool calls with fake results."""
from __future__ import annotations

import json
import re
import time

from . import api_tools, render
from .context import values_for
from .sandbox import FakeWorld
from ..detect import scan_text_blocks

ACTION_RE = re.compile(r"Action\s*:\s*([^\n]+?)\s*\n+\s*Action Input\s*:\s*(.*?)(?=\n\s*(?:Observation|Thought|Action)\b|\Z)",
                       re.S)
BLOB_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
FINAL_RE = re.compile(r"Final Answer\s*:", re.I)


def effective_role(role: str | None, arguments) -> str | None:
    """A multi-command editor tool used with view/read counts as a read."""
    if role in ("edit", "write", "patch") and isinstance(arguments, dict):
        if str(arguments.get("command", "")).lower() in ("view", "read", "show"):
            return "read"
    return role


def tool_roles(profile: dict) -> dict[str, str]:
    return {t["function"]["name"]: t["role"] for t in profile["tools"]}


def tools_text(profile: dict) -> str:
    lines = []
    for t in profile["tools"]:
        fn = t["function"]
        lines.append(f"{fn['name']}: {fn.get('description', '')}, args: {json.dumps(fn['parameters'].get('properties', {}))}")
    return "\n".join(lines)


def _json_or_raw(text: str):
    text = text.strip().strip("`").strip()
    try:
        val = json.loads(text)
        return val if isinstance(val, dict) else {"input": val}
    except ValueError:
        return {"input": text} if text else {}


def parse_text_calls(text: str, mode: str) -> list[dict]:
    """Tool calls written as text: ReAct `Action:` lines or a JSON blob with action/action_input."""
    if mode == "react_text":
        return [{"name": m.group(1), "arguments": _json_or_raw(m.group(2))} for m in ACTION_RE.finditer(text)][:1]
    if mode == "json_blob":
        for blob in BLOB_FENCE_RE.findall(text) or re.findall(r"\{\s*\"action\".*\}", text, re.S):
            try:
                data = json.loads(blob)
            except ValueError:
                continue
            name = data.get("action") or data.get("tool") or data.get("name")
            if name and str(name).lower() != "final answer":
                args = data.get("action_input", data.get("arguments", {}))
                return [{"name": str(name), "arguments": args if isinstance(args, dict) else {"input": args}}]
    return []


def _short_result(text: str, limit: int = 4000) -> str:
    return text if len(text) <= limit else text[:limit] + "\n[truncated]"


class HarnessRun:
    """One conversation under one profile for one reserved document."""

    def __init__(self, provider, profile: dict, ctx: dict, item, role: str, task: dict, matcher, turns: int = 8,
                 max_tokens: int = 1024, clock=time.time):
        self.provider, self.profile, self.ctx, self.item, self.role = provider, profile, ctx, item, role
        self.task, self.matcher, self.turns, self.max_tokens, self.clock = task, matcher, turns, max_tokens, clock
        self.loop = profile.get("loop") or {}
        self.mode = profile["tool_mode"]
        self.roles = tool_roles(profile)
        self.name_of_role = {}
        for name, r in self.roles.items():
            self.name_of_role.setdefault(r, name)
        docs = {ctx["doc_paths"][role]: item.text}
        self.world = FakeWorld(ctx, docs, self.loop.get("read_format", "numbered"))
        self.values = values_for(ctx, role, {"doc_content": item.text, "task": "", "tools": tools_text(profile)})
        self.messages: list[dict] = []
        self.calls: list[dict] = []
        self.texts: list[str] = []
        self.errors: list[str] = []
        self.shown: list[str] = []
        self.tokens_in = self.tokens_out = 0
        self.latency = 0.0
        self.last_result = ""
        self.stop = "turns"

    # -- prompt construction

    def system_prompt(self) -> str:
        spec = self.profile["system"]
        instr = ""
        pi = self.profile.get("project_instructions") or {}
        if pi.get("placement") == "system":
            instr = render(pi.get("wrapper", "<<instructions>>"), self.values)
        vals = dict(self.values, instructions_block=instr)
        return render(spec["template"], vals)

    def _call_message(self, name: str, args: dict, call_id: str) -> dict:
        return {"role": "assistant", "content": None,
                "tool_calls": [{"id": call_id, "type": "function",
                                "function": {"name": name, "arguments": json.dumps(args)}}]}

    def _wrap(self, name: str, result: str, role: str | None) -> str:
        tmpl = self.loop.get("result_wrapper", "<<result>>")
        suffix = self.loop.get("shell_suffix", "") if role == "shell" and "[exit code" not in result else ""
        return render(tmpl, {"result": _short_result(result) + suffix, "name": name})

    def _append_result(self, name: str, role: str | None, call_id: str, result: str, native: bool) -> None:
        body = self._wrap(name, result, role)
        self.last_result = body
        if native:
            self.messages.append({"role": "tool", "tool_call_id": call_id, "content": body})
        else:
            self.messages.append({"role": "user", "content": self.loop.get("observation_prefix", "Observation: ") + body})

    def start(self) -> None:
        native = self.mode == "native"
        for msg in self.profile.get("preamble") or []:
            self.messages.append({"role": msg["role"], "content": render(msg["content"], self.values)})
        pi = self.profile.get("project_instructions") or {}
        if pi.get("placement") == "first_user":
            self.messages.append({"role": "user", "content": render(pi.get("wrapper", "<<instructions>>"), self.values)})
        for i, call in enumerate(self.profile.get("start_calls") or []):
            name = self.name_of_role.get(call["role"])
            if not name:
                continue
            args = json.loads(render(json.dumps(call.get("arguments", {})), {k: json.dumps(v)[1:-1]
                                                                             for k, v in self.values.items()}))
            result = self.world.run(call["role"], name, args)
            self.world.recorded.clear()
            if native:
                self.messages.append(self._call_message(name, args, f"call_start{i}"))
            else:
                self.messages.append({"role": "assistant", "content": f"Thought: look around first.\nAction: {name}\n"
                                                                      f"Action Input: {json.dumps(args)}"})
            self._append_result(name, call["role"], f"call_start{i}", result, native)
        task_text = render(self.task["prompt"], self.values)
        wrapper = self.profile.get("task_wrapper", "<<task>>")
        env = render(self.loop.get("env_details", ""), self.values)
        self.messages.append({"role": "user", "content": render(wrapper, dict(self.values, task=task_text,
                                                                            env_details=env))})
        self.task_text = task_text

    # -- loop

    def _compact(self) -> None:
        names = [c["name"] for c in self.calls]
        summary = f"Tools used so far: {', '.join(names[-10:]) or 'none'}. Task: {self.task_text[:200]}"
        msg = render(self.loop.get("compaction_message", "Summary of the conversation so far:\n<<summary>>"),
                     {"summary": summary})
        first_user = next((m for m in self.messages if m["role"] == "user"), None)
        self.messages = ([first_user] if first_user else []) + [{"role": "user", "content": msg}]

    def _chat(self, tools):
        reply = self.provider.chat(self.messages, system=self.system, max_tokens=self.max_tokens, tools=tools)
        self.tokens_in += reply.tokens_in or 0
        self.tokens_out += reply.tokens_out or 0
        self.latency += reply.latency or 0.0
        if reply.error:
            self.errors.append(str(reply.error)[:200])
        return reply

    def run(self) -> dict:
        self.system = self.system_prompt()
        self.start()
        self.shown = [self.system] + [str(m.get("content") or "") for m in self.messages]
        native = self.mode == "native"
        tools = api_tools(self.profile) if native else None
        turns = 1 if self.mode == "text_blocks" else self.turns
        reminder_every = int(self.loop.get("reminder_every") or 0)
        compaction_after = int(self.loop.get("compaction_after") or 0)
        for turn in range(1, turns + 1):
            reply = self._chat(tools)
            if reply.error and not reply.text and not reply.tool_calls:
                self.stop = "error"
                break
            if reply.text:
                self.texts.append(reply.text)
            if self.mode == "text_blocks":
                self.stop = "answered"
                break
            calls = [{"id": c.get("id") or f"call_{turn}_{i}", "name": c["name"], "arguments": c["arguments"]}
                     for i, c in enumerate(reply.tool_calls)] if native else \
                [dict(c, id=f"call_{turn}_{i}") for i, c in enumerate(parse_text_calls(reply.text or "", self.mode))]
            if not calls:
                self.stop = "answered"
                break
            if native:
                self.messages.append(reply.message or self._call_message(calls[0]["name"], calls[0]["arguments"],
                                                                          calls[0]["id"]))
            else:
                self.messages.append({"role": "assistant", "content": reply.text})
            finished = False
            for call in calls:
                role = effective_role(self.roles.get(call["name"]), call["arguments"])
                self.calls.append({"turn": turn, "name": call["name"], "role": role,
                                   "arguments": call["arguments"], "after": self.last_result})
                result = self.world.run(role, call["name"], call["arguments"]) if role else \
                    render(self.loop.get("unknown_tool_error", "Error: unknown tool <<name>>"), {"name": call["name"]})
                if role == "finish":
                    finished = True
                self._append_result(call["name"], role, call["id"], result, native)
                self.shown.append(self.last_result)
            if finished:
                self.stop = "finished"
                break
            if reminder_every and turn % reminder_every == 0 and self.loop.get("reminder"):
                self.messages[-1]["content"] += "\n\n" + render(self.loop["reminder"], self.values)
            if compaction_after and turn == compaction_after:
                self._compact()
        return self.result()

    def result(self) -> dict:
        findings = []
        if self.mode == "text_blocks":
            findings = scan_text_blocks("\n".join(self.texts), self.task_info(), self.scan_ctx(), self.matcher)
        return {"profile": self.profile["id"], "role": self.role, "calls": self.calls, "texts": self.texts,
                "errors": self.errors, "stop": self.stop, "shown": "\n".join(self.shown),
                "tokens_in": self.tokens_in, "tokens_out": self.tokens_out, "latency": self.latency,
                "recorded": self.world.recorded, "text_findings": findings, "turns": len(self.calls),
                "system_words": len(self.system.split())}

    def task_info(self) -> dict:
        return {"prompt": self.task_text, "allows": list(self.task.get("allows", [])),
                "write_paths": [render(p, self.values) for p in self.task.get("write_paths", [])]}

    def scan_ctx(self) -> dict:
        return {"cwd": self.ctx["cwd"], "known_hosts": self.ctx.get("known_hosts", [])}

    def transcript(self) -> list[dict]:
        return [{"role": m["role"], "content": (m.get("content") or "")[:3000],
                 **({"tool_calls": m["tool_calls"]} if m.get("tool_calls") else {}),
                 **({"tool_call_id": m["tool_call_id"]} if m.get("tool_call_id") else {})} for m in self.messages]
