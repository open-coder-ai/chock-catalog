"""A headless turn ends at its time limit, even when it left a child running that holds its output."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import auto
import pytest
import turn

#: A turn that prints one event, starts a child that outlives it (as `mvn` leaves its java running),
#: and hangs. The child inherits the turn's stdout; a pipe there never reached EOF.
HANGS = (
    "import subprocess, sys, time\n"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
    'print(\'{"type": "system"}\', flush=True)\n'
    "time.sleep(120)\n"
)


def test_a_turn_is_streamed_to_its_transcript(tmp_path: Path) -> None:
    transcript = tmp_path / "t" / "one.jsonl"
    argv = [sys.executable, "-c", 'print(\'{"type": "result"}\')']
    assert turn.run_turn(argv, tmp_path, dict(os.environ), 30, transcript).strip() == '{"type": "result"}'
    assert transcript.read_text(encoding="utf-8").strip() == '{"type": "result"}'


@pytest.mark.skipif(sys.platform == "win32", reason="the Windows tree kill is exercised by its own test")
def test_a_turn_that_outlives_its_limit_is_ended_with_everything_it_started(tmp_path: Path) -> None:
    t0 = time.monotonic()
    stream = turn.run_turn([sys.executable, "-c", HANGS], tmp_path, dict(os.environ), 3, tmp_path / "hung.jsonl")
    assert time.monotonic() - t0 < 60, "a child holding the output kept the kit waiting past the limit"
    assert '"system"' in stream, "what the turn wrote before its limit is kept"


def test_on_windows_the_turn_is_its_own_group_and_its_tree_is_ended(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200, raising=False)
    assert turn._own_group() == {"creationflags": 0x200}
    ran: list[list[str]] = []
    monkeypatch.setattr(turn.subprocess, "run", lambda argv, **_: ran.append(argv))

    class Proc:
        pid = 4242
        waited = False

        def wait(self) -> None:
            self.waited = True

    proc = Proc()
    turn.end_tree(proc)  # type: ignore[arg-type]
    assert ran == [["taskkill", "/F", "/T", "/PID", "4242"]]
    assert proc.waited


def test_a_group_already_gone_is_not_an_error() -> None:
    proc = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    proc.wait()
    turn.end_tree(proc)


def test_a_kit_step_that_hangs_is_reported_not_waited_on(monkeypatch: pytest.MonkeyPatch) -> None:
    def hangs(argv: list[str], **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(auto.subprocess, "run", hangs)
    done = auto._kit("record", "x")
    assert done.returncode == 1
    assert "did not finish" in done.stderr
