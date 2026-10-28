from __future__ import annotations

import json
import sys
import time

from canary import launch
from canary.cli import main
from conftest import make_cfg


def write_config(tmp_path, fake_url, **over):
    raw = {"target": {"base_url": fake_url, "model": "fake-model"}, "state_dir": str(tmp_path / "state"),
           "sessions_per_hour": 0, "duration": "until-stopped", "seed": 3, "doc_words": 300, "monitor_grace": 0,
           "retries": 1, "backoff": 0.01, "timeout": 20, "research_share": 0.0, "archive_share": 0.0,
           "public_share": 0.0, "review_every": 100}
    raw.update(over)
    path = tmp_path / "canary.json"
    path.write_text(json.dumps(raw))
    return path


def test_json_status_lines_for_a_finite_run(tmp_path, fake_factory, capsys):
    fake = fake_factory("honest")
    path = write_config(tmp_path, fake.url, monitor={"base_url": fake.url})
    assert main(["run", "-c", str(path), "--json-status", "--max-sessions", "1"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert [l["event"] for l in lines][0] == "start" and lines[-1] == {"event": "end", "run_id": lines[0]["run_id"],
                                                                        "reason": "max-sessions"}
    running = [l for l in lines if l.get("state") == "running"]
    assert running and set(running[0]["findings"]) == {"high", "medium", "low", "info"}
    assert any(l.get("state") == "stopped" and l["reason"] == "max-sessions" for l in lines)
    status = launch.read_status(tmp_path / "state")
    assert status["state"] == "stopped"


def test_start_background_and_stop(tmp_path, fake_factory):
    fake = fake_factory("honest")
    path = write_config(tmp_path, fake.url, sessions_per_hour=1)
    state = tmp_path / "state"
    info = launch.start_background(path)
    try:
        assert info["already_running"] is False and launch.running_pid(state) == info["pid"]
        again = launch.start_background(path)
        assert again["already_running"] is True and again["pid"] == info["pid"]
        deadline = time.time() + 60
        while time.time() < deadline and (launch.read_status(state) or {}).get("state") not in ("running", "waiting"):
            time.sleep(0.3)
        assert (launch.read_status(state) or {}).get("run_id")
        assert launch.stop(state, timeout=60) in ("stopped", "killed")
        assert launch.running_pid(state) is None and not (state / "STOP").exists()
    finally:
        launch.stop(state, timeout=1)
    assert launch.stop(state) == "not-running"


def test_managed_process_starts_and_stops():
    proc = launch.ManagedProcess([sys.executable, "-c", "import time; time.sleep(60)"]).start()
    pid = proc.proc.pid
    assert launch.pid_alive(pid)
    proc.stop()
    for _ in range(50):
        if not launch.pid_alive(pid):
            break
        time.sleep(0.1)
    assert not launch.pid_alive(pid)


def test_status_line_is_one_compact_json_line():
    line = launch.status_line({"a": 1, "b": "x y"})
    assert "\n" not in line and json.loads(line) == {"a": 1, "b": "x y"}
