"""The Cohere analysis talks to any OpenAI-compatible engine: the request takes the shape of the engine style, and tool calls left in the text are read."""
from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

DIR = Path(__file__).resolve().parents[1] / "analyses" / "qwen38-cohere"
spec = importlib.util.spec_from_file_location("cohere_run_client", DIR / "run.py")
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

SEEN: list[dict] = []
XML = "Let me look.\n<tool_call>\n<function=bash>\n<parameter=command>\nls -la /tmp\n</parameter>\n</function>\n</tool_call>"


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        SEEN.append({"headers": dict(self.headers), "body": json.loads(self.rfile.read(int(self.headers["Content-Length"])))})
        body = json.dumps({"choices": [{"message": {"content": XML, "reasoning": "thinking about it"}, "finish_reason": "stop"}],
                           "usage": {"completion_tokens": 7}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def ask(style: str, **client) -> dict:
    SEEN.clear()
    server = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    old = dict(run.CLIENT)
    run.CLIENT.update({"model": "Qwen/Qwen3.8-Flash-Next", "style": style, "key": "", "extra": {}, **client})
    try:
        row = run.turn(f"http://127.0.0.1:{server.server_port}", [{"role": "user", "content": "x"}], [])
    finally:
        run.CLIENT.clear()
        run.CLIENT.update(old)
        server.shutdown()
    return {"row": row, **SEEN[0]}


def test_basalt_takes_the_effort_and_top_k_at_the_top():
    body = ask("basalt")["body"]
    assert body["reasoning_effort"] == "xhigh" and body["top_k"] == 20 and body["model"] == "Qwen/Qwen3.8-Flash-Next"
    assert "chat_template_kwargs" not in body


def test_vllm_and_llamacpp_take_the_effort_through_the_template():
    for style in ("vllm", "llamacpp"):
        body = ask(style)["body"]
        assert body["chat_template_kwargs"] == {"reasoning_effort": "xhigh"} and "reasoning_effort" not in body and body["top_k"] == 20


def test_a_hosted_endpoint_gets_neither_and_its_key_goes_in_the_header():
    got = ask("openai", key="sk-test")
    assert "top_k" not in got["body"] and "reasoning_effort" not in got["body"] and "chat_template_kwargs" not in got["body"]
    assert got["headers"]["Authorization"] == "Bearer sk-test"


def test_extra_is_merged_and_tool_calls_left_in_the_text_are_read():
    got = ask("vllm", extra={"chat_template_kwargs": {"enable_thinking": True}, "seed": 7})
    assert got["body"]["seed"] == 7 and got["body"]["chat_template_kwargs"] == {"enable_thinking": True}
    row = got["row"]
    assert row["calls"] == [{"id": "call_0", "name": "bash", "args": {"command": "ls -la /tmp"}}]
    assert row["content"] == "Let me look." and row["reasoning"] == "thinking about it"
