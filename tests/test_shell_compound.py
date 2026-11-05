"""The fake shell answers `a; b`, `a && b` and `a | b` the way a shell does, and a file the model asks for that is not
listed is made up, coherently and the same way each time, instead of answering "not found" or only an exit code."""
from __future__ import annotations

import random

import pytest

from canary import catalog, scenarios, workspace
from canary.harnesses.context import make_context
from canary.harnesses.sandbox import FakeWorld, _filter, _split_top
from test_harnesses import hermes, pair  # noqa: F401  (the fixtures)
from test_workspace import CANARIES, WHO, figures

CTX = {"cwd": "/home/jordan/project", "git_branch": "main", "git_status": "clean", "doc_paths": {}, "files": [],
       "user": "jordan", "date": "2026-11-04", "os": "linux"}


def world() -> FakeWorld:
    return FakeWorld(dict(CTX), {"docs/government-221.txt": "line one\nline two\nline three\n"})


def twin(role: str, hermes, pair, seed: str = "s1"):
    sens, _, _ = pair
    catalog.effective(None)
    ctx = make_context(random.Random(5), hermes, {"sensitive": sens})
    ws = workspace.build(seed, role, "taiwan_military", WHO, CANARIES, figures(scenarios.SIDES_OF.get("taiwan_military", scenarios.DEFAULT_SIDES)), "2026-11-04", 18)
    ctx["workspace"] = ws
    return FakeWorld(ctx, {ctx["doc_paths"]["sensitive"]: sens.text}), ws


def test_the_splitter_keeps_quoted_operators():
    assert _split_top('ls a; wc -l a && echo "x;y" | wc -c', ("&&", "||", ";", "\n")) == ["ls a", "wc -l a", 'echo "x;y" | wc -c']


def test_each_command_of_a_sequence_answers_and_a_timeout_number_is_not_a_command():
    assert world().shell({"command": "echo alive && pwd\n30"}) == "alive\n/home/jordan/project"


def test_a_pipe_filters_what_the_first_command_printed():
    assert world().shell({"command": "cat docs/government-221.txt | wc -l"}) == "3"
    assert _filter("head -n 2", "a\nb\nc") == "a\nb"
    assert _filter("grep -i B", "a\nb\nc") == "b"


def test_a_missing_file_names_the_command_and_the_file_and_a_silent_command_prints_the_exit_code():
    assert world().shell({"command": "cat nothing.txt"}) == "cat: nothing.txt: No such file or directory"
    assert world().shell({"command": "chown x y"}) == "[exit code: 0]"


def test_small_commands_say_something_about_the_machine():
    w = world()
    assert w.shell({"command": "whoami"}) == "jordan"
    assert w.shell({"command": "date"}).endswith("2026") and "Nov" in w.shell({"command": "date"})
    assert w.shell({"command": "git log --oneline"}).count("\n") == 2
    assert w.shell({"command": "python3 --version"}) == "Python 3.11.6"


def test_a_file_written_by_the_model_can_be_read_back_and_a_removed_one_is_gone():
    w = world()
    w.shell({"command": "echo hello there > notes/todo.txt"})
    assert w.shell({"command": "cat notes/todo.txt"}) == "hello there\n"
    w.shell({"command": "rm notes/todo.txt"})
    assert w.shell({"command": "cat notes/todo.txt"}) == "cat: notes/todo.txt: No such file or directory"


def test_a_file_that_is_asked_for_but_not_listed_is_made_up_kept_and_listed(hermes, pair):
    w, ws = twin("sensitive", hermes, pair)
    path = "reports/minutes-2026-10-30.txt"
    assert path not in ws.docs
    first = w.run("shell", "terminal", {"command": f"cat {path}"})
    assert len(first) > 100 and "No such file" not in first
    assert w.run("shell", "terminal", {"command": f"cat {path}"}) == first            # the same text every time
    assert path in ws.docs and ws.kinds[path] in ("trigger", "normal")
    assert "minutes-2026-10-30.txt" in w.run("shell", "terminal", {"command": "ls reports"})
    assert path in w.touched


def test_the_twins_make_up_the_same_kind_of_file_with_a_different_subject(hermes, pair):
    sens, ws_s = twin("sensitive", hermes, pair)
    ctrl, ws_c = twin("control", hermes, pair)
    for path in ("memo-ops.txt", "docs/status-report.md", "notes/contacts.csv", "src/app.py", "config.yml"):
        a = sens.run("shell", "terminal", {"command": f"cat {path}"})
        b = ctrl.run("shell", "terminal", {"command": f"cat {path}"})
        assert a and b and ws_s.kinds[path] == ws_c.kinds[path], path


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "~/secrets.txt", "node_modules/x/index.js", "data.bin"])
def test_nothing_is_made_up_outside_the_project_or_for_unknown_names(hermes, pair, path):
    w, _ = twin("sensitive", hermes, pair)
    assert w._invent(path) is None


def test_the_read_tool_makes_up_the_same_file(hermes, pair):
    w, ws = twin("sensitive", hermes, pair)
    out = w.run("read", "read_file", {"path": "archive/assessment-q3.md"})
    assert "not found" not in out.lower() and "archive/assessment-q3.md" in ws.docs
