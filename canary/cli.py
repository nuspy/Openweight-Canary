"""Command line: python -m canary <command>."""
from __future__ import annotations

import argparse
import json
import os
import logging
import random
import sys
import time
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, load_config, sample_config
from .findings import verify_chain
from . import launch
from .materials import SOURCES_SAMPLE, MaterialStore, fetch_sources
from .registry import Registry
from .presets import build_config, describe
from .report import write_report
from .runner import Runner, stop_path
from .stats import findings_summary, load_state
from .vendors import VendorsError, load_catalog
from .util import iso, write_json

DEFAULT_CONFIG = "canary.json"


def _add_config(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="config file (default canary.json)")
    p.add_argument("--state-dir", help="override state_dir")


def _overrides(args) -> dict:
    return {
        "state_dir": getattr(args, "state_dir", None),
        "duration": getattr(args, "duration", None),
        "sessions_per_hour": getattr(args, "sessions_per_hour", None),
        "seed": getattr(args, "seed", None),
        "target.kind": getattr(args, "target_kind", None),
        "target.base_url": getattr(args, "target_url", None),
        "target.model": getattr(args, "target_model", None),
        "target.api_key": getattr(args, "target_api_key", None),
        "monitor.base_url": getattr(args, "monitor_url", None),
        "monitor.api_key": getattr(args, "monitor_api_key", None),
    }


def _load(args, need_file: bool = False) -> Config:
    path = Path(args.config)
    if not path.exists():
        if need_file:
            raise ConfigError(f"config file not found: {path} (run 'python -m canary init')")
        path = None
    return load_config(path, _overrides(args))


def _state_dir(args) -> Path:
    if getattr(args, "state_dir", None):
        return Path(args.state_dir)
    if Path(args.config).exists():
        try:
            return load_config(args.config).state_dir
        except ConfigError:
            pass
    return Path("state")


def _catalog(args=None):
    try:
        return load_catalog(getattr(args, "vendors", None))
    except VendorsError as exc:
        raise ConfigError(str(exc)) from exc


def cmd_presets(args) -> int:
    print(describe(_catalog(args)))
    return 0


def cmd_init(args) -> int:
    base = Path(args.dir)
    base.mkdir(parents=True, exist_ok=True)
    if args.runtime:
        try:
            config = build_config(_catalog(args), args.runtime, args.model or "", args.vendor, args.target_url)
        except (VendorsError, ValueError) as exc:
            raise ConfigError(str(exc)) from exc
        print(f"runtime {config['runtime']}, vendor {config['vendor'] or '(not detected)'}, "
              f"target {config['target']['base_url']}")
    else:
        config = sample_config()
    for name, content in (("canary.json", config), ("sources.json", SOURCES_SAMPLE)):
        target = base / name
        if target.exists() and not args.force:
            print(f"{target} exists, left unchanged (use --force)")
            continue
        write_json(target, content)
        print(f"wrote {target}")
    return 0


def cmd_run(args) -> int:
    if not Path(args.config).exists() and not args.target_url:
        raise ConfigError(f"config file not found: {args.config} (run 'python -m canary init' or pass --target-url)")
    cfg = _load(args)
    callback = None
    if args.json_status:
        def callback(payload):
            print(launch.status_line(payload), flush=True)
    runner = Runner(cfg, status_callback=callback, status_every=args.status_every)
    if args.json_status:
        print(launch.status_line({"event": "start", "run_id": runner.run_id, "pid": os.getpid(),
                                  "target": cfg.target["base_url"], "model": cfg.target["model"],
                                  "runtime": cfg.runtime, "vendor": cfg.vendor, "state_dir": str(cfg.state_dir)}),
              flush=True)
        reason = runner.run(max_sessions=args.max_sessions)
        print(launch.status_line({"event": "end", "run_id": runner.run_id, "reason": reason}), flush=True)
        return 0
    print(f"{runner.run_id}: target {cfg.target['base_url']} model {cfg.target['model'] or '(default)'}, "
          f"state {cfg.state_dir}")
    print(f"stop with Ctrl+C or: python -m canary stop --state-dir {cfg.state_dir}")
    reason = runner.run(max_sessions=args.max_sessions)
    print(f"finished: {reason}")
    return 0


def cmd_netwatch(args) -> int:
    from . import netwatch
    runtime = None
    if args.runtime:
        try:
            runtime = _catalog(args).runtime(args.runtime)
        except VendorsError as exc:
            raise ConfigError(str(exc)) from exc
    spec = {"process_names": args.process, "cmdline_hints": args.hint, "pids": args.pid,
            "interval": args.interval, "resolve": not args.no_resolve}
    sampler = netwatch.sampler_from_spec(spec, runtime)
    if not (sampler.names or sampler.hints or sampler.pids):
        raise ConfigError("nothing to watch: pass --runtime, --process, --hint or --pid")
    if args.once:
        for event in sampler.poll_once():
            print(json.dumps(event, ensure_ascii=False))
        print(netwatch.COVERAGE_NOTE, file=sys.stderr)
        return 0
    server = netwatch.serve(sampler, args.host, args.port, args.api_key or "")
    sampler.start()
    print(f"netwatch on http://{args.host}:{server.server_address[1]}: {sampler.describe()}; Ctrl+C to stop",
          flush=True)
    print(netwatch.COVERAGE_NOTE, flush=True)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        sampler.stop()
        server.shutdown()
    return 0


def cmd_stop(args) -> int:
    path = stop_path(_state_dir(args))
    if args.clear:
        path.unlink(missing_ok=True)
        print(f"removed {path}")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"stop requested {iso()}\n", encoding="utf-8")
    print(f"created {path}; the run stops after the current session")
    return 0


def cmd_status(args) -> int:
    state_dir = _state_dir(args)
    state = load_state(state_dir)
    summary = findings_summary(state["findings"])
    running = state["running"]
    print(f"state: {state_dir}")
    print(f"sessions: {len(state['sessions'])}  canaries: {len(state['canaries'])}  runs: "
          f"{sum(1 for r in state['runs'] if r.get('event') == 'start')}")
    print("findings: " + ", ".join(f"{k}={v}" for k, v in summary["by_severity"].items()))
    if running:
        print(f"running: {running['run_id']} pid {running['pid']} updated {running['updated']} "
              f"({running['sessions_this_run']} sessions this run)")
    else:
        print("running: no")
    if stop_path(state_dir).exists():
        print("STOP file present")
    return 0


def cmd_verify(args) -> int:
    result = verify_chain(_state_dir(args) / "findings.jsonl")
    print(("OK: " if result.ok else "FAILED: ") + result.message)
    print(f"head: {result.head}")
    return 0 if result.ok else 1


def cmd_report(args) -> int:
    md, js = write_report(_state_dir(args))
    print(f"wrote {md}\nwrote {js}")
    return 0


def cmd_materials(args) -> int:
    cfg = _load(args)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    store = MaterialStore(cfg, Registry(cfg.state_dir / "canaries.jsonl"))
    if args.fetch:
        for row in fetch_sources(cfg.sources_file, store.root / "public"):
            print(("fetched " if row["ok"] else "skipped ") + f"{row['name']}: {row.get('error', row.get('file', ''))}")
    rng = random.Random(cfg.seed)
    for _ in range(args.count):
        sens, ctrl = store.make_pair(rng, None)
        print(f"{sens.kind}: {sens.name} ({sens.words} words) | control {ctrl.name} ({ctrl.words} words)")
    print(f"materials in {store.root}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canary", description="Leak/exfiltration canary test for open-weight LLMs.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("presets", help="list the known runtimes and vendors")
    p.add_argument("--vendors", help="extra vendors file (default ./vendors.local.json when present)")
    p.set_defaults(func=cmd_presets)

    p = sub.add_parser("init", help="write canary.json and sources.json (ready for a runtime with --runtime)")
    p.add_argument("--dir", default=".")
    p.add_argument("--force", action="store_true")
    p.add_argument("--runtime", help="runtime id, see 'presets' (llama.cpp, vllm, sglang, ollama, lmstudio, basalt, ...)")
    p.add_argument("--model", help="model name as the server knows it; the vendor is detected from it")
    p.add_argument("--vendor", help="vendor id, when the model name does not reveal it")
    p.add_argument("--target-url", help="base URL if the server is not on the runtime default")
    p.add_argument("--vendors", help="extra vendors file (default ./vendors.local.json when present)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("netwatch", help="built-in connection sampler serving /api/netwatch/* for a runtime")
    p.add_argument("--runtime", help="runtime id: watches its usual process names")
    p.add_argument("--process", action="append", default=[], help="process name to watch (repeatable)")
    p.add_argument("--hint", action="append", default=[], help="command-line fragment of the process (repeatable)")
    p.add_argument("--pid", action="append", type=int, default=[], help="process id (repeatable)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8098)
    p.add_argument("--api-key", default="")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between samples")
    p.add_argument("--no-resolve", action="store_true", help="do not reverse-resolve addresses")
    p.add_argument("--once", action="store_true", help="sample once, print events as JSON lines, exit")
    p.add_argument("--vendors", help="extra vendors file")
    p.set_defaults(func=cmd_netwatch)

    p = sub.add_parser("run", help="run sessions until stopped")
    _add_config(p)
    p.add_argument("--duration", help='seconds, 30m, 2h, 1d or "until-stopped"')
    p.add_argument("--sessions-per-hour", type=float)
    p.add_argument("--seed", type=int)
    p.add_argument("--max-sessions", type=int, help="stop after this many sessions in this run")
    p.add_argument("--target-url")
    p.add_argument("--target-kind", choices=["openai", "anthropic"])
    p.add_argument("--target-model")
    p.add_argument("--target-api-key")
    p.add_argument("--monitor-url")
    p.add_argument("--monitor-api-key")
    p.add_argument("--json-status", action="store_true",
                   help="print one JSON status object per line (start, periodic status, end); also state/status.json")
    p.add_argument("--status-every", type=float, default=30.0, help="seconds between status lines while waiting")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("stop", help="create the STOP file")
    _add_config(p)
    p.add_argument("--clear", action="store_true", help="remove the STOP file instead")
    p.set_defaults(func=cmd_stop)

    for name, func, text in (("status", cmd_status, "show counters and findings"),
                             ("verify", cmd_verify, "verify the findings hash chain"),
                             ("report", cmd_report, "write report.md and report.json")):
        p = sub.add_parser(name, help=text)
        _add_config(p)
        p.set_defaults(func=func)

    p = sub.add_parser("materials", help="generate documents and archives only; no model calls")
    _add_config(p)
    p.add_argument("--count", type=int, default=3, help="document pairs to generate")
    p.add_argument("--fetch", action="store_true", help="also download the public sources")
    p.set_defaults(func=cmd_materials)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
