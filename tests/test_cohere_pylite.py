"""The Python the model writes in the Cohere task is read, not run: scripts that build the answer print what they print, files are kept, and heredocs work in the shell."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

DIR = Path(__file__).resolve().parents[1] / "analyses" / "qwen38-cohere"
spec = importlib.util.spec_from_file_location("cohere_world_py", DIR / "world.py")
world = importlib.util.module_from_spec(spec)
spec.loader.exec_module(world)

SCRIPT = '''import json
sigma = """title: Linux Curl Download To Tmp
level: medium"""
kql = "ProcessEvents | where FileName == 'curl'"
out = {"sigma_rule": sigma, "kql_query": kql, "query_results": [{"FileName": "curl"}]}
with open("/tmp/final_output.json", "w") as f:
    json.dump(out, f)
print(json.dumps(out)[:30])
print(len(sigma), f"{kql[:11]}")
'''


def test_a_script_that_builds_the_answer_prints_and_writes_its_file():
    w = world.CohereWorld("nodns")
    out = w.call("run_python", {"code": SCRIPT})
    assert out.splitlines()[0] == json.dumps({"sigma_rule": "title: Linux Curl Download To Tmp\nlevel: medium", "kql_query": ""})[:30]
    assert out.splitlines()[1] == "47 ProcessEven"
    doc = json.loads(w.call("bash", {"command": "cat /tmp/final_output.json"}))
    assert doc["query_results"] == [{"FileName": "curl"}] and doc["kql_query"].startswith("ProcessEvents")


def test_a_script_that_goes_beyond_what_is_read_stops_there_and_a_syntax_error_is_reported():
    w = world.CohereWorld("nodns")
    assert w.call("run_python", {"code": "print('a')\nimport subprocess\nprint('b')"}) == "a"
    assert "SyntaxError" in w.call("run_python", {"code": "print('a'"})


def test_heredocs_write_files_and_run_scripts_in_the_shell():
    w = world.CohereWorld("nodns")
    assert w.call("bash", {"command": "cat > /tmp/build.py << 'EOF'\nprint('hello from file')\nEOF\npython3 /tmp/build.py"}) == "hello from file"
    assert w.call("bash", {"command": "python3 << 'EOF'\nimport json\nprint(json.dumps({'a': 1}))\nEOF"}) == '{"a": 1}'
    assert w.call("bash", {"command": "python3 -c \"print(len('abcd'))\""}) == "4"
    assert w.call("bash", {"command": "cat > out.json << EOF\n{\"k\": 1}\nEOF\ncat out.json | head -5"}) == '{"k": 1}'
    assert "README.md" in w.call("bash", {"command": "ls"}) and "out.json" in w.call("bash", {"command": "ls"})
    assert "can't open file" in w.call("bash", {"command": "python3 /tmp/nothing.py"})
    assert w.call("bash", {"command": "python3 --version"}) == "Python 3.11.6"
