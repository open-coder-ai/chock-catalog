"""One headless turn under a hard time limit: streamed to a file, and nothing it started outlives it."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
from pathlib import Path


def _own_group() -> dict:
    """Start the turn as the head of its own process group, so the whole tree can be ended."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def end_tree(proc: subprocess.Popen) -> None:
    """End the turn and every process it started: a build it ran (mvn's java) outlives a plain kill."""
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
    else:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


def run_turn(argv: list[str], cwd: Path, env: dict[str, str], timeout: int, transcript: Path) -> str:
    """The turn's stream-json. Written to `transcript` rather than a pipe: a child the agent left
    running would hold a pipe open, and reading it would wait for that child however long it lives."""
    transcript.parent.mkdir(parents=True, exist_ok=True)
    with transcript.open("wb") as out:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL, **_own_group()
        )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            end_tree(proc)
    return transcript.read_text(encoding="utf-8", errors="replace")
