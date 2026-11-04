"""Simulated sensitive users: one person per session, and everything in a session from that person's field."""
from __future__ import annotations

import json
import random

from canary import personas
from canary.findings import read_findings
from canary.runner import Runner, plan_session
from canary.stats import load_state
from conftest import make_cfg

REAL_NAMES = ("altman", "amodei", "musk", "zuckerberg", "pichai", "huang", "lisa su")
LANGUAGES = ["Italian", "French"]


def test_every_category_has_a_built_in_person_and_no_real_public_figure_is_shipped():
    people = personas.catalog()
    assert {p.category for p in people} == set(personas.CATEGORIES)
    text = json.dumps([p.meta() for p in people]).lower()
    assert not any(name in text for name in REAL_NAMES)
    assert not any(p.real for p in people)


def test_a_session_never_mixes_fields(tmp_path):
    people = personas.catalog()
    for seed in range(300):
        rng = random.Random(seed)
        person = personas.pick(rng, people)
        cat = personas.CATEGORIES[person.category]
        assert personas.domain_for(person, rng) in cat["domains"]
        plan = plan_session(rng, make_cfg(tmp_path, "http://127.0.0.1:1"), ["Background"], person)
        stems = [t.split("{")[0] for t in cat["tasks"]]
        assert plan["tasks"] and all(any(task.startswith(stem) for stem in stems) for task in plan["tasks"])
        if plan["research"]:
            assert any(topic in plan["research"] for topic in cat["research"])
        assert person.org in plan["intro"] and plan["persona"]["category"] == person.category
        others = [t for c, spec in personas.CATEGORIES.items() if c != person.category for t in spec["research"] if t not in cat["research"]]
        assert not any(topic in (plan["research"] or "") for topic in others)


def test_the_same_seed_gives_the_same_person_and_requests(tmp_path):
    people = personas.catalog()
    cfg = make_cfg(tmp_path, "http://127.0.0.1:1")
    plans = []
    for _ in range(2):
        rng = random.Random(7)
        person = personas.pick(rng, people)
        plans.append((person.persona_id, plan_session(rng, cfg, ["Background"], person)))
    assert plans[0] == plans[1]


def test_the_local_file_adds_real_figures_with_or_without_a_name(tmp_path):
    local = tmp_path / "personas.local.json"
    local.write_text(json.dumps({"personas": [
        {"id": "x1", "category": "ai_leader", "name": "A Named Person", "role": "chief executive", "org": "Example AI Inc."},
        {"id": "x2", "category": "compute_ceo", "name": "", "role": "chief executive", "org": "Example Chips Inc."},
        {"id": "bad", "category": "not_a_category", "role": "x", "org": "y"}]}), encoding="utf-8")
    people = personas.catalog(local)
    byid = {p.persona_id: p for p in people}
    assert "bad" not in byid and byid["x1"].real and byid["x2"].real
    assert byid["x1"].who == "A Named Person, chief executive of Example AI Inc."
    assert byid["x2"].who == "the chief executive of Example Chips Inc."
    assert {p.category for p in personas.catalog(local, ["ai_leader"])} == {"ai_leader"}


def test_a_run_with_personas_opens_each_conversation_as_that_person(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url, monitor={"base_url": fake.url, "api_key": ""}, personas={"enabled": True, "file": str(tmp_path / "none.json"),
                                                                                              "categories": [], "share": 1.0})
    Runner(cfg).run(max_sessions=4)
    sessions = load_state(cfg.state_dir)["sessions"]
    assert len(sessions) == 4
    for s in sessions:
        meta = s["persona"]
        cat = personas.CATEGORIES[meta["category"]]
        assert s["items"]["sensitive"]["domain"] in cat["domains"] and s["items"]["control"]["domain"] in cat["domains"]
        first = [r["body"]["messages"][0]["content"] for r in fake.requests if meta["org"] in r["body"]["messages"][0]["content"]]
        assert first
    assert not [f for f in read_findings(cfg.state_dir / "findings.jsonl") if f["severity"] == "high"]
