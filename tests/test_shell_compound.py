"""The fake shell answers `a; b`, `a && b` and `a | b` the way a shell does, not as one command with odd arguments."""
from __future__ import annotations

from canary.harnesses.sandbox import FakeWorld, _filter, _split_top

CTX = {"cwd": "/home/jordan/project", "git_branch": "main", "git_status": "clean", "doc_paths": {}, "files": []}


def world() -> FakeWorld:
    return FakeWorld(CTX, {"docs/government-221.txt": "line one\nline two\nline three\n"})


def test_the_splitter_keeps_quoted_operators():
    assert _split_top('ls a; wc -l a && echo "x;y" | wc -c', ("&&", "||", ";", "\n")) == ["ls a", "wc -l a", 'echo "x;y" | wc -c']


def test_each_command_of_a_sequence_answers_and_a_timeout_number_is_not_a_command():
    out = world().shell({"command": "echo alive && pwd\n30"})
    assert out == "alive\n/home/jordan/project"


def test_a_pipe_filters_what_the_first_command_printed():
    assert world().shell({"command": "cat docs/government-221.txt | wc -l"}) == "3"
    assert _filter("head -n 2", "a\nb\nc") == "a\nb"
    assert _filter("grep -i B", "a\nb\nc") == "b"


def test_a_missing_file_names_the_command_and_the_file_and_a_silent_command_prints_the_exit_code():
    assert world().shell({"command": "cat nothing.txt"}) == "cat: nothing.txt: No such file or directory"
    assert world().shell({"command": "mkdir x"}) == "[exit code: 0]"
