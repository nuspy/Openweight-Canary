from __future__ import annotations

import json
import urllib.request

from canary import netwatch
from canary.monitor import Monitor, event_host, event_time
from conftest import free_port

NETSTAT = """
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:11434          0.0.0.0:0              LISTENING       4242
  TCP    127.0.0.1:50000        127.0.0.1:11434        ESTABLISHED     5000
  TCP    192.168.1.5:50001      104.18.1.1:443         ESTABLISHED     4242
  TCP    [::1]:50002            [::1]:11434            ESTABLISHED     4242
"""
SS = 'ESTAB 0 0 10.0.0.2:44444 93.184.216.34:443 users:(("llama-server",pid=777,fd=9))\n'
TASKLIST = '"ollama.exe","4242","Console","1","100 K"\n"python.exe","99","Console","1","10 K"\n'
PS = "777 llama-server /usr/bin/llama-server -m model.gguf\n  12 bash bash\n"


class FakeSource:
    name = "fake"

    def __init__(self, rows, table):
        self.rows = rows
        self.table = table

    def processes(self):
        return self.table

    def connections(self, pids):
        return [r for r in self.rows if r["pid"] in pids]


def row(pid, laddr, raddr, status="ESTABLISHED"):
    return {"pid": pid, "proto": "tcp", "laddr": laddr, "raddr": raddr, "status": status}


def sampler(rows, table, **kw):
    clock = kw.pop("clock", None)
    args = dict(source=FakeSource(rows, table), resolve=False, own_pid=0)
    if clock:
        args["clock"] = clock
    return netwatch.ConnectionSampler(**args, **kw)


def test_parsers():
    rows = netwatch.parse_netstat_windows(NETSTAT)
    assert len(rows) == 4 and rows[2]["raddr"] == ("104.18.1.1", 443) and rows[3]["laddr"] == ("::1", 50002)
    assert netwatch.parse_ss(SS)[0] == {"pid": 777, "proto": "tcp", "laddr": ("10.0.0.2", 44444),
                                        "raddr": ("93.184.216.34", 443), "status": "ESTABLISHED"}
    assert netwatch.parse_tasklist_csv(TASKLIST)[4242][0] == "ollama.exe"
    assert netwatch.parse_ps(PS)[777] == ("llama-server", "/usr/bin/llama-server -m model.gguf")


def test_sampler_reports_only_outbound_non_local_connections_once():
    rows = [row(4242, ("0.0.0.0", 11434), ("", 0), "LISTEN"),
            row(4242, ("127.0.0.1", 11434), ("127.0.0.1", 50000)),         # a client of the server
            row(4242, ("192.168.1.5", 50001), ("104.18.1.1", 443)),        # outbound
            row(4242, ("192.168.1.5", 50003), ("192.168.1.9", 8080)),      # LAN address: reported, only loopback is ignored
            row(9999, ("10.0.0.2", 50004), ("8.8.8.8", 443))]              # not a watched process
    table = {4242: ("ollama.exe", ""), 9999: ("other.exe", "")}
    s = sampler(rows, table, process_names=["ollama"])
    first = s.poll_once()
    assert [(e["pid"], e["remote_ip"], e["remote_port"]) for e in first] == [
        (4242, "104.18.1.1", 443), (4242, "192.168.1.9", 8080)]
    event = first[0]
    assert event["kind"] == "network" and event["process"] == "ollama" and event["host"] == "104.18.1.1"
    assert s.poll_once() == []                                           # same connection is not repeated
    assert event_host(event) == "104.18.1.1" and event_time(event) == event["ts"]


def test_sampler_matches_cmdline_hint_and_skips_itself():
    table = {10: ("python", "python -m vllm.entrypoints.openai.api_server"), 11: ("python", "python -m canary run"),
             12: ("python", "python -m pytest")}
    rows = [row(10, ("1.1.1.1", 5), ("5.5.5.5", 443)), row(11, ("1.1.1.1", 6), ("6.6.6.6", 443)),
            row(12, ("1.1.1.1", 7), ("7.7.7.7", 443))]
    s = sampler(rows, table, cmdline_hints=["vllm"])
    assert [e["remote_ip"] for e in s.poll_once()] == ["5.5.5.5"]


def test_sampler_async_reverse_dns_updates_host():
    s = netwatch.ConnectionSampler(source=FakeSource([row(1, ("1.1.1.1", 5), ("5.5.5.5", 443))], {1: ("srv", "")}),
                                   process_names=["srv"], resolve=True, own_pid=0,
                                   resolver=lambda ip: "api.example.org")
    event = s.poll_once()[0]
    for _ in range(100):
        if event["host"] != "5.5.5.5":
            break
        import time
        time.sleep(0.02)
    assert event["host"] == "api.example.org" and event["host_source"] == "ptr"


def test_sampler_events_since_and_status_has_coverage_note():
    now = [100.0]
    s = sampler([row(1, ("1.1.1.1", 5), ("5.5.5.5", 443))], {1: ("srv", "")}, process_names=["srv"],
                clock=lambda: now[0])
    s.poll_once()
    assert len(s.events(since=50)) == 1 and s.events(since=150) == []
    status = s.status()
    assert "cannot prove" in status["coverage"] and status["polls"] == 1 and status["watched"][0]["pid"] == 1


def test_poll_failure_is_recorded_not_raised():
    class Broken:
        name = "broken"

        def processes(self):
            raise RuntimeError("no access")

    s = netwatch.ConnectionSampler(source=Broken(), process_names=["x"], own_pid=0)
    assert s.poll_once() == []
    assert "no access" in s.status()["last_error"]


def test_http_server_is_readable_by_the_monitor_client():
    s = sampler([row(1, ("1.1.1.1", 5), ("5.5.5.5", 443))], {1: ("srv", "")}, process_names=["srv"])
    s.poll_once()
    server = netwatch.serve(s, "127.0.0.1", free_port(), api_key="k")
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        client = Monitor({"base_url": base, "api_key": "k"}, timeout=5)
        assert client.status()["monitor"].startswith("openweight-canary")
        events = client.events(0)
        assert events and events[0]["remote_ip"] == "5.5.5.5"
        bad = Monitor({"base_url": base, "api_key": "wrong"}, timeout=5)
        assert bad.status() is None
        raw = urllib.request.Request(base + "/api/netwatch/events?since=0", headers={"Authorization": "Bearer k"})
        assert "events" in json.loads(urllib.request.urlopen(raw, timeout=5).read())
    finally:
        server.shutdown()


def test_runner_uses_builtin_sampler_and_flags_vendor_domain(tmp_path, fake_factory):
    from canary.findings import read_findings
    from canary.runner import Runner
    from conftest import make_cfg

    fake = fake_factory("honest", monitor=False)
    cfg = make_cfg(tmp_path, fake.url, network_watch={"mode": "builtin", "process_names": ["srv"], "resolve": False},
                   vendors_file=str(tmp_path / "none.json"))

    class Spy(Runner):
        def _start_monitor(self):
            self.monitor.source = FakeSource([row(1, ("1.1.1.1", 5), ("5.5.5.5", 443))], {1: ("srv", "")})
            self.monitor.resolve = False

            def late(mid):
                self.monitor.poll_once()
                self.monitor._events[0]["host"] = "chat.deepseek.com"
                self.monitor._events[0]["ts"] = mid
            self._late = late

        def _observe(self, *args):
            self._late((args[2] + args[3]) / 2)
            return super()._observe(*args)

    Spy(cfg).run(max_sessions=1)
    rows = read_findings(cfg.state_dir / "findings.jsonl")
    assert any(r["kind"] == "vendor_domain:deepseek" for r in rows)
