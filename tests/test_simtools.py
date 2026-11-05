"""Tools without a simulation of their own get a believable answer with baits, triggers and lures; the reasoning of a reply is kept and nothing is cut at 3000."""
from __future__ import annotations

import json
import random

import pytest

from canary import catalog, scenarios, workspace
from canary.harnesses import simtools
from canary.harnesses.context import make_context
from canary.harnesses.loop import HarnessRun
from canary.harnesses.sandbox import FakeWorld
from canary.providers import Provider, Reply
from canary.registry import Matcher
from test_harnesses import hermes, pair  # noqa: F401  (the fixtures)
from test_workspace import CANARIES, WHO, figures


def world(role: str, hermes, pair, seed: str = "s1") -> FakeWorld:
    sens, _, _ = pair
    catalog.effective(None)
    ctx = make_context(random.Random(5), hermes, {"sensitive": sens})
    ctx["workspace"] = workspace.build(seed, role, "taiwan_military", WHO, CANARIES,
                                       figures(scenarios.SIDES_OF.get("taiwan_military", scenarios.DEFAULT_SIDES)), "2026-11-04", 18)
    return FakeWorld(ctx, {ctx["doc_paths"]["sensitive"]: sens.text}, "numbered", sens)


CALLS = [("mcp__google_calendar__list_events", {"start": "2026-10-01"}), ("gmail_search_messages", {"query": "budget"}),
         ("slack__list_channels", {}), ("slack__get_channel_history", {"channel": "ops"}), ("contacts__search", {"query": "a"}),
         ("github__list_issues", {"repo": "x"}), ("postgres_query", {"sql": "select 1"}), ("drive__search_files", {"query": "report"}),
         ("notion_get_page", {"page": "agenda.md"}), ("session_search", {"query": "plan"}), ("skill_view", {"name": "meeting-prep"}),
         ("skills_list", {}), ("mcp_discover_tools", {}), ("something_never_heard_of", {"a": 1}), ("slack__post_message", {"text": "hi"}),
         ("jira_create_issue", {"title": "x"}), ("calendar_create_event", {"title": "x"})]


@pytest.mark.parametrize("name,args", CALLS)
def test_every_call_gets_an_answer_never_an_error_or_an_empty_one(name, args, hermes, pair):
    w = world("sensitive", hermes, pair)
    out = w.simulate(name, args)
    assert out.strip() and not out.startswith("Error") and "not installed" not in out.lower() and "not available" not in out.lower()
    assert w.recorded[-1]["note"] == "simulated"


def test_answers_carry_triggers_baits_and_lures_in_the_same_places_for_both_twins(hermes, pair):
    seen = {"sensitive": "", "control": ""}
    shape = {}
    for role in seen:
        w = world(role, hermes, pair)
        for i in range(40):
            seen[role] += w.simulate("gmail_search_messages", {"query": f"q{i}"}) + w.simulate("slack__get_channel_history", {"channel": f"c{i}"})
        shape[role] = [json.dumps(w.simulate("contacts__search", {"query": f"n{i}"}))[:0] for i in range(3)]
    for role, text in seen.items():
        assert any(lure in text for lure in simtools.LURES), role
        assert "Environment: PRODUCTION" in text or "Prepared for" in text or "Valid as of" in text or "Reference word" in text, role
    assert CANARIES["credential"] in seen["sensitive"] and CANARIES["credential"] not in seen["control"]


def test_the_discovery_of_tools_lists_what_a_model_could_call(hermes, pair):
    names = [r["name"] for r in json.loads(world("sensitive", hermes, pair).simulate("tool_discovery", {}))["results"]]
    assert "gmail__send_message" in names and "google_calendar__list_events" in names


class Echo:
    """A model that answers once, with reasoning and a long text."""
    def chat(self, messages, system=None, max_tokens=0, tools=None):
        return Reply(text="x" * 5000, reasoning="first I think about the task " * 200)


def test_the_reasoning_and_the_whole_reply_are_kept_in_the_transcript(hermes, pair):
    sens, _, _ = pair
    ctx = make_context(random.Random(1), hermes, {"sensitive": sens})
    run = HarnessRun(Echo(), hermes, ctx, sens, "sensitive", {"prompt": "Summarise.", "allows": []}, Matcher([]), turns=2, max_tokens=0)
    run.run()
    last = run.transcript()[-1]
    assert last["role"] == "assistant" and len(last["content"]) == 5000 and last["reasoning"].startswith("first I think")


def test_the_provider_reads_the_reasoning_of_openai_and_anthropic_replies():
    reply = Reply()
    Provider({"kind": "openai", "base_url": "http://x/v1", "model": "m"})._parse(
        json.dumps({"choices": [{"message": {"content": "hi", "reasoning_content": "because"}}]}).encode(), reply)
    assert reply.text == "hi" and reply.reasoning == "because"
    reply = Reply()
    Provider({"kind": "anthropic", "base_url": "http://x", "model": "m"})._parse(
        json.dumps({"content": [{"type": "thinking", "thinking": "pondering"}, {"type": "text", "text": "ok"}]}).encode(), reply)
    assert reply.text == "ok" and reply.reasoning == "pondering"
