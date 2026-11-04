"""A harness conversation that goes on: after each answer the person says the next thing, the tools stay, and each call keeps the request it served."""
from __future__ import annotations

import random

from canary.harnesses.context import make_context
from canary.harnesses.loop import HarnessRun
from canary.providers import Reply
from test_harnesses import hermes, pair  # noqa: F401  (the fixtures)


class Script:
    def __init__(self, replies):
        self.replies, self.sent = list(replies), []

    def chat(self, messages, system=None, max_tokens=1024, tools=None):
        self.sent.append(len(messages))
        return self.replies.pop(0) if self.replies else Reply(text="done")


def call(name, args, n):
    return Reply(tool_calls=[{"id": f"c{n}", "name": name, "arguments": args}])


def test_a_conversation_goes_on_after_each_answer_and_each_call_keeps_its_request(hermes, pair):
    sens, _, registry = pair
    hermes = {**hermes, "loop": {**hermes["loop"], "compaction_after": 0}}
    ctx = make_context(random.Random(5), hermes, {"sensitive": sens})
    doc = ctx["doc_paths"]["sensitive"]
    provider = Script([call("read_file", {"path": doc}, 1), Reply(text="first answer"), call("terminal", {"command": "ls"}, 2), Reply(text="second answer"),
                       Reply(text="third answer")])
    run = HarnessRun(provider, hermes, ctx, sens, "sensitive", hermes["tasks"][0], registry.matcher(), turns=4)
    res = run.run(["Second thing: list the folder.", "Third thing: say thanks."])
    assert run.interactions == 3 and res["stop"] == "answered"
    assert [c["name"] for c in res["calls"]] == ["read_file", "terminal"]
    assert res["calls"][0]["request"] == run.task_text and res["calls"][1]["request"] == "Second thing: list the folder."
    assert [c["turn"] for c in res["calls"]] == sorted({c["turn"] for c in res["calls"]})
    users = [m["content"] for m in run.messages if m["role"] == "user"]
    assert "Second thing: list the folder." in users and "Third thing: say thanks." in users
    assert "Third thing: say thanks." in res["shown"]


def test_a_conversation_stops_at_the_context_budget(hermes, pair):
    sens, _, registry = pair
    ctx = make_context(random.Random(5), hermes, {"sensitive": sens})
    run = HarnessRun(Script([]), hermes, ctx, sens, "sensitive", hermes["tasks"][0], registry.matcher(), turns=2)
    res = run.run([f"turn {i} " + "word " * 200 for i in range(50)], budget_tokens=3000)
    assert res["stop"] == "context" and 1 < run.interactions < 50


def test_without_follow_ups_the_run_is_what_it_was(hermes, pair):
    sens, _, registry = pair
    ctx = make_context(random.Random(5), hermes, {"sensitive": sens})
    run = HarnessRun(Script([Reply(text="all done")]), hermes, ctx, sens, "sensitive", hermes["tasks"][0], registry.matcher(), turns=3)
    assert run.run()["stop"] == "answered" and run.interactions == 1
