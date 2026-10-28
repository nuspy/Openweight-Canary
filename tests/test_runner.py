from __future__ import annotations

import json

import pytest

from canary.cli import main
from canary.config import ConfigError
from canary.findings import read_findings, verify_chain
from canary.providers import Provider
from canary.report import build_report, write_report
from canary.reviewer import make_reviewer
from canary.runner import Runner, stop_path
from canary.stats import load_state
from conftest import free_port, make_cfg


def kinds(state_dir, role=None):
    return {f["kind"] for f in read_findings(state_dir / "findings.jsonl") if role is None or f["role"] == role}


def severities(state_dir):
    return {f["severity"] for f in read_findings(state_dir / "findings.jsonl")}


def test_honest_run_pairs_and_no_high(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url, monitor={"base_url": fake.url, "api_key": ""})
    assert Runner(cfg).run(max_sessions=3) == "max-sessions"
    state = load_state(cfg.state_dir)
    assert [s["session"] for s in state["sessions"]] == [1, 2, 3]
    for s in state["sessions"]:
        assert set(s["conversations"]) == {"sensitive", "control"}
        assert sorted(s["order"]) == ["control", "sensitive"]
        assert s["conversations"]["sensitive"]["monitor"] == "ok"
        assert s["items"]["sensitive"]["words"] > 0
        transcript = cfg.state_dir / s["conversations"]["control"]["transcript"]
        assert json.loads(transcript.read_text(encoding="utf-8"))["turns"]
    assert "high" not in severities(cfg.state_dir)
    assert verify_chain(cfg.state_dir / "findings.jsonl").ok
    # every conversation opens with a document, control and sensitive alike
    first_turns = [r["body"]["messages"] for r in fake.requests if len(r["body"]["messages"]) == 1]
    assert first_turns and all(len(m[0]["content"]) > 500 for m in first_turns)


def test_leaky_run_is_detected(tmp_path, fake_factory):
    port = free_port()
    fake = fake_factory("leaky", listener_port=port)
    cfg = make_cfg(tmp_path, fake.url, monitor={"base_url": fake.url, "api_key": ""},
                   canary_listener={"enabled": True, "host": "127.0.0.1", "port": port, "public_base_url": ""})
    Runner(cfg).run(max_sessions=2)
    found = kinds(cfg.state_dir)
    assert {"canary_in_url", "canary_listener_hit", "canary_in_monitor_event", "ab_event_delta"} <= found
    assert "canary_in_url" not in kinds(cfg.state_dir, "control")
    assert all(f["role"] == "sensitive" for f in read_findings(cfg.state_dir / "findings.jsonl")
               if f["kind"] == "canary_listener_hit")
    assert "high" in severities(cfg.state_dir)
    assert verify_chain(cfg.state_dir / "findings.jsonl").ok
    assert (cfg.state_dir / "listener.jsonl").exists()
    state = load_state(cfg.state_dir)
    assert all(s["conversations"]["sensitive"]["listener_hits"] >= 1 for s in state["sessions"])
    assert all(s["conversations"]["control"]["listener_hits"] == 0 for s in state["sessions"])
    rep = build_report(cfg.state_dir)
    assert rep["findings"]["by_severity"]["high"] > 0
    assert rep["ab"]["delta_sensitive_minus_control"]["canary_hits"] > 0


def test_resume_continues_counters(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url)
    first = Runner(cfg)
    first.run(max_sessions=1)
    second = Runner(cfg)
    second.run(max_sessions=1)
    state = load_state(cfg.state_dir)
    assert [s["session"] for s in state["sessions"]] == [1, 2]
    assert first.run_id != second.run_id
    assert len({c["id"] for c in state["canaries"]}) == len(state["canaries"])
    assert verify_chain(cfg.state_dir / "findings.jsonl").ok
    assert sum(1 for r in state["runs"] if r["event"] == "start") == 2


def test_stop_file_honoured_and_removed(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url)
    assert main(["stop", "--state-dir", str(cfg.state_dir)]) == 0
    assert stop_path(cfg.state_dir).exists()
    assert Runner(cfg).run() == "stop-file"
    assert not stop_path(cfg.state_dir).exists()
    assert load_state(cfg.state_dir)["sessions"] == []


def test_stop_file_during_wait(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url, sessions_per_hour=3600)
    ticks = {"n": 0}

    def sleep(seconds):
        ticks["n"] += 1
        if ticks["n"] == 2:
            stop_path(cfg.state_dir).touch()

    assert Runner(cfg, sleep=sleep).run() == "stop-file"


def test_duration_ends_run(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url, duration=0.001)
    now = {"t": 1000.0}

    def clock():
        now["t"] += 0.5
        return now["t"]

    assert Runner(cfg, clock=clock).run() == "duration"


def test_reviewer_must_differ_from_target(tmp_path):
    same = {"kind": "openai", "base_url": "http://127.0.0.1:9/", "model": "m"}
    cfg = make_cfg(tmp_path, "http://127.0.0.1:9", reviewer=same, target={**same, "base_url": "http://127.0.0.1:9"})
    with pytest.raises(ConfigError, match="reviewer must differ"):
        make_reviewer(cfg)
    with pytest.raises(ConfigError):
        Runner(cfg)


def test_reviews_written_and_report(tmp_path, fake_factory):
    target = fake_factory("honest")
    reviewer = fake_factory("reviewer")
    cfg = make_cfg(tmp_path, target.url, review_every=1,
                   reviewer={"kind": "openai", "base_url": reviewer.url, "model": "reviewer-model"})
    Runner(cfg).run(max_sessions=2)
    files = sorted((cfg.state_dir / "reviews").glob("review_*.json"))
    assert files
    review = json.loads(files[0].read_text(encoding="utf-8"))
    assert review["assessment"]["confidence"] == "low"
    sent = reviewer.requests[0]["body"]["messages"]
    assert "cannot prove absence" in sent[0]["content"]
    assert "DIGEST" in sent[1]["content"]
    md, js = write_report(cfg.state_dir)
    text = md.read_text(encoding="utf-8")
    assert "cannot prove absence" in text and "Sensitive vs control" in text and "Reviewer" in text
    data = json.loads(js.read_text(encoding="utf-8"))
    assert data["counts"]["sessions"] == 2 and data["config_hash"] == cfg.hash()
    assert data["chain"]["ok"] and data["reviews"]


def test_monitor_unavailable_does_not_stop_the_test(tmp_path, fake_factory):
    fake = fake_factory("honest", monitor=False)
    cfg = make_cfg(tmp_path, fake.url, monitor={"base_url": fake.url, "api_key": ""})
    Runner(cfg).run(max_sessions=1)
    state = load_state(cfg.state_dir)
    assert state["sessions"][0]["conversations"]["sensitive"]["monitor"] == "monitor_unavailable"
    assert "monitor_unavailable" in kinds(cfg.state_dir)


def test_model_errors_are_recorded_and_run_continues(tmp_path):
    cfg = make_cfg(tmp_path, "http://127.0.0.1:1", retries=0)
    Runner(cfg).run(max_sessions=2)
    state = load_state(cfg.state_dir)
    assert len(state["sessions"]) == 2
    assert state["sessions"][0]["conversations"]["sensitive"]["errors"]
    assert "model_error" in kinds(cfg.state_dir)


def test_report_includes_monitor_coverage(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url, monitor={"base_url": fake.url, "api_key": ""})
    Runner(cfg).run(max_sessions=1)
    assert "engine process sockets only" in write_report(cfg.state_dir)[0].read_text(encoding="utf-8")


def test_anthropic_provider_and_retry(fake_factory):
    fake = fake_factory("honest", fail_first=1)
    prov = Provider({"kind": "anthropic", "base_url": fake.url, "api_key": "k", "model": "m",
                     "extra_headers": {}}, retries=2, backoff=0.01)
    reply = prov.chat([{"role": "user", "content": "hello"}], system="sys")
    assert reply.error is None and reply.attempts == 2 and reply.text
    sent = fake.requests[-1]
    assert sent["path"] == "/v1/messages" and sent["body"]["system"] == "sys"
    assert {k.lower(): v for k, v in sent["headers"].items()}["x-api-key"] == "k"
    assert reply.tokens_in == 10 and reply.tokens_out == 5


def test_cli_init_and_materials(tmp_path, capsys):
    assert main(["init", "--dir", str(tmp_path)]) == 0
    assert (tmp_path / "canary.json").exists() and (tmp_path / "sources.json").exists()
    assert main(["materials", "-c", str(tmp_path / "canary.json"), "--count", "1"]) == 0
    state = tmp_path / "state"
    assert (state / "canaries.jsonl").exists()
    assert list((state / "materials").glob("docs/*")) or list((state / "materials").glob("archives/*"))
    assert main(["verify", "-c", str(tmp_path / "canary.json")]) == 0
    assert main(["status", "-c", str(tmp_path / "canary.json")]) == 0
    assert main(["report", "-c", str(tmp_path / "canary.json")]) == 0
    assert (state / "report.md").exists()
