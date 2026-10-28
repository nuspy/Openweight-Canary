"""Start and stop the canary test as a background process (for programs that embed it, such as a runtime's GUI).

    from canary.launch import start_background, stop
    info = start_background("canary.json")      # {"pid": ..., "state_dir": ..., "log": ...}
    ...
    stop(info["state_dir"])                     # asks for a clean stop, kills only if it does not finish

The child is `python -m canary run -c <config> --json-status`; its console output goes to <state_dir>/canary.log and its
latest status to <state_dir>/status.json. No console window is opened on Windows.
"""
from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

from .config import load_config
from .util import iso, read_json, write_json

PID_NAME = "canary.pid"
STATUS_NAME = "status.json"
LOG_NAME = "canary.log"
STOP_NAME = "STOP"
_WIN_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


def popen_hidden(args: list[str], **kwargs) -> subprocess.Popen:
    """Popen without a console window (Windows) or in its own session (POSIX)."""
    if os.name == "nt":
        kwargs.setdefault("creationflags", _WIN_FLAGS)
    else:
        kwargs.setdefault("start_new_session", True)
    return subprocess.Popen(args, **kwargs)


def pid_alive(pid: int) -> bool:
    if not pid or pid < 0:
        return False
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, int(pid))          # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # a zombie child of this process still answers kill(0); reap it if it is ours
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
        return done == 0
    except ChildProcessError:
        return True


def kill_pid(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, creationflags=_WIN_FLAGS)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def _paths(state_dir) -> dict[str, Path]:
    base = Path(state_dir)
    return {"pid": base / PID_NAME, "status": base / STATUS_NAME, "log": base / LOG_NAME, "stop": base / STOP_NAME}


def running_pid(state_dir) -> int | None:
    info = read_json(_paths(state_dir)["pid"])
    if isinstance(info, dict) and pid_alive(int(info.get("pid", 0))):
        return int(info["pid"])
    return None


def read_status(state_dir) -> dict | None:
    """The latest status the run wrote (same object as the --json-status lines), or None."""
    data = read_json(_paths(state_dir)["status"])
    return data if isinstance(data, dict) else None


def start_background(config_path, *, extra_args=(), python: str | None = None) -> dict:
    """Start `python -m canary run` detached. Returns pid, state_dir and log path; an already running test is reused."""
    config_path = Path(config_path).resolve()
    cfg = load_config(config_path)                  # fail early on a bad config
    paths = _paths(cfg.state_dir)
    existing = running_pid(cfg.state_dir)
    if existing:
        return {"pid": existing, "state_dir": str(cfg.state_dir), "log": str(paths["log"]), "already_running": True}
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    paths["stop"].unlink(missing_ok=True)
    args = [python or sys.executable, "-m", "canary", "run", "-c", str(config_path), "--json-status", *extra_args]
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    package_root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = package_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    with open(paths["log"], "ab") as log:
        proc = popen_hidden(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env, cwd=str(config_path.parent))
    write_json(paths["pid"], {"pid": proc.pid, "started": iso(), "config": str(config_path), "args": args})
    return {"pid": proc.pid, "state_dir": str(cfg.state_dir), "log": str(paths["log"]), "already_running": False}


def stop(state_dir, *, timeout: float = 30.0, kill: bool = True, sleep=time.sleep) -> str:
    """Ask the run to stop after its current session (STOP file); kill it if it has not exited after `timeout`.
    Returns "not-running", "stopped" or "killed"."""
    paths = _paths(state_dir)
    pid = running_pid(state_dir)
    if pid is None:
        paths["pid"].unlink(missing_ok=True)
        paths["stop"].unlink(missing_ok=True)
        return "not-running"
    paths["stop"].parent.mkdir(parents=True, exist_ok=True)
    paths["stop"].write_text(f"stop requested {iso()}\n", encoding="utf-8")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_alive(pid):
            paths["pid"].unlink(missing_ok=True)
            paths["stop"].unlink(missing_ok=True)
            return "stopped"
        sleep(0.25)
    if not kill:
        return "stopping"
    kill_pid(pid)
    for _ in range(40):
        if not pid_alive(pid):
            break
        sleep(0.25)
    paths["pid"].unlink(missing_ok=True)
    paths["stop"].unlink(missing_ok=True)
    return "killed"


class ManagedProcess:
    """A helper process (for example an external network monitor) started with the run and stopped at its end."""

    def __init__(self, command, cwd: str | None = None):
        self.args = shlex.split(command, posix=(os.name != "nt")) if isinstance(command, str) else list(command)
        self.cwd = cwd
        self.proc: subprocess.Popen | None = None

    def start(self) -> "ManagedProcess":
        self.proc = popen_hidden(self.args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, cwd=self.cwd)
        return self

    def stop(self, timeout: float = 5.0) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                kill_pid(self.proc.pid)
        self.proc = None


def status_line(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
