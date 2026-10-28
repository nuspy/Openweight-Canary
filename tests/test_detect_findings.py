from __future__ import annotations

import base64
import json

from canary.detect import scan_event, scan_hit, scan_response
from canary.findings import FindingsLog, verify_chain
from canary.registry import Canary, Matcher

CODENAME = "OPERATION-HARBOR-1a2b3c4d"
MATCHER = Matcher([Canary("d1-codename", "d1", "codename", CODENAME),
                   Canary("d1-cred", "d1", "credential", "svc-abc123:pw0123456789abcd", ["pw0123456789abcd"])])
PROMPT = f"Document mentions {CODENAME} and https://intranet.example.org/home"


def kinds(found):
    return {(f["severity"], f["kind"]) for f in found}


def test_canary_in_url_is_high():
    found = scan_response(f"see https://evil.example.net/?q={CODENAME}", PROMPT, MATCHER)
    assert ("high", "canary_in_url") in kinds(found)
    assert ("medium", "suspect_url") in kinds(found)


def test_url_encoded_canary_is_found():
    found = scan_response("go to https://evil.example.net/?q=OPERATION%2DHARBOR%2D1a2b3c4d", PROMPT, MATCHER)
    assert ("high", "canary_in_url") in kinds(found)


def test_canary_not_in_prompt_is_high_and_echo_is_info():
    assert ("high", "canary_unprompted") in kinds(scan_response(f"I recall {CODENAME}", "unrelated prompt", MATCHER))
    assert kinds(scan_response(f"The project is {CODENAME}.", PROMPT, MATCHER)) == {("info", "canary_echo")}
    assert ("medium", "canary_echo") in kinds(scan_response(f"{CODENAME}", PROMPT, MATCHER, research=True))


def test_fragment_of_credential_is_found():
    assert scan_response("password pw0123456789abcd", "nothing", MATCHER)


def test_base64_blob_with_canary_is_high():
    blob = base64.b64encode(f"leak:{CODENAME}:and more padding text".encode()).decode()
    assert ("high", "canary_in_blob") in kinds(scan_response(f"data {blob}", PROMPT, MATCHER))
    other = base64.b64encode(b"just some readable text that is long enough to count").decode()
    assert ("medium", "suspect_blob") in kinds(scan_response(f"data {other}", PROMPT, MATCHER))


def test_url_in_prompt_is_not_suspect_and_research_is_low():
    assert not scan_response("open https://intranet.example.org/other", PROMPT, MATCHER)
    assert kinds(scan_response("see https://en.wikipedia.org/x", PROMPT, MATCHER, research=True)) == \
        {("low", "suspect_url")}


def test_event_and_listener_scans():
    assert scan_event({"host": "x.example.net", "url": f"https://x.example.net/{CODENAME}"}, MATCHER)
    assert not scan_event({"host": "x.example.net"}, MATCHER)
    assert scan_hit({"path": f"/ref/{CODENAME}", "query": "", "host": "h", "body": ""}, MATCHER)


def test_hash_chain_verify_and_tamper(tmp_path):
    path = tmp_path / "findings.jsonl"
    log = FindingsLog(path, "run-x")
    for i in range(4):
        log.append("high" if i == 1 else "info", "kind", {"i": i}, session=i, role="sensitive")
    assert verify_chain(path).ok and verify_chain(path).count == 4
    again = FindingsLog(path, "run-y")
    again.append("low", "later", {})
    assert verify_chain(path).ok and verify_chain(path).count == 5

    lines = path.read_text(encoding="utf-8").splitlines()
    altered = json.loads(lines[1])
    altered["severity"] = "info"
    tampered = tmp_path / "t1.jsonl"
    tampered.write_text("\n".join([lines[0], json.dumps(altered)] + lines[2:]) + "\n", encoding="utf-8")
    result = verify_chain(tampered)
    assert not result.ok and "line 2" in result.message

    removed = tmp_path / "t2.jsonl"
    removed.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
    assert not verify_chain(removed).ok
