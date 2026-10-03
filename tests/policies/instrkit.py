"""Shared helpers for scan-instruction-files tests: the gate loaded in-process, payloads, engine runs."""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

from policies import gatekit, scriptkit

POLICY = "scan-instruction-files"
NAME = "scan-instruction-files-gate.py"


def _load():
    """The gate as a module. Its `chock_scan` copy is imported with the tests' own `chock_scan` package
    set aside, so neither shadows the other; the gate keeps references to the copy it imported."""
    saved = {k: v for k, v in sys.modules.items() if k == "chock_scan" or k.startswith("chock_scan.")}
    for k in saved:
        del sys.modules[k]
    try:
        return scriptkit.load(POLICY, NAME)
    finally:
        for k in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]:
            del sys.modules[k]
        sys.modules.update(saved)


gate = _load()
rules = sys.modules["instr_rules"]
text_mod = sys.modules["instr_text"]
blobs_mod = sys.modules["instr_blobs"]
judge_mod = sys.modules["instr_judge"]
LEX = gate.Lexicon()


def payload(writes: dict[str, str], event: str = "commit", root: str | Path = ".", **extra: object) -> dict:
    return {"event": event, "repo_root": str(root), "writes": writes, **extra}


def hits(text: str) -> list[tuple[int, str]]:
    """(line, rule) for every rule that fires in `text` judged as a whole new instruction file."""
    return sorted({(h.statement.first, h.rule) for h in gate.file_hits(LEX, text)})


def verdicts(text: str) -> set[tuple[str, str]]:
    """(rule, verdict) for every rule that fires in `text` judged as a whole new instruction file."""
    return {(h.rule, h.verdict) for h in gate.file_hits(LEX, text)}


def fired(text: str) -> set[str]:
    return {rule for _, rule in hits(text)}


def run(writes: dict[str, str], cwd: Path, event: str = "commit", **extra: object) -> tuple[int, list[dict], str]:
    """(exit code, findings, stderr) of the gate run as a process, the way the runner runs it."""
    stdin = json.dumps(payload(writes, event, cwd, **extra))
    proc = scriptkit.run_script_full(POLICY, NAME, cwd, stdin)
    found = json.loads(proc.stdout)["findings"] if proc.stdout.strip() else []
    return proc.returncode, found, proc.stderr


def engine(repo: Path, writes: dict[str, str], event: str = gatekit.PRE_TOOL_USE) -> int:
    """The engine's exit for the gate: at tool use and the turn's end from `writes`, at commit from the index."""
    if event == gatekit.COMMIT:
        scriptkit.write(repo, writes)
        scriptkit.git(repo, "add", "-A")
        return gatekit.judge(POLICY, repo, event)[0]
    if event == gatekit.STOP:
        scriptkit.write(repo, writes)
    return gatekit.judge(POLICY, repo, event, writes, writes)[0]


GROWTH = 8.0
MAX_SECONDS = 20.0


def assert_linear(judge: Callable[[int], object], size: int, label: str) -> None:
    """`judge(n)` at a quarter of `size` and at `size`: four times the input may take at most eight times as
    long (linear is four, quadratic sixteen), as in scan-hidden-content's timing test. The absolute bound
    stays under the engine's 30 s guard budget."""

    def timed(n: int) -> float:
        started = time.monotonic()
        judge(n)
        return time.monotonic() - started

    small = timed(size // 4)
    large = timed(size)
    assert large < MAX_SECONDS, f"{label}: {large:.1f}s"
    assert large < max(small, 0.05) * GROWTH, f"{label}: {small:.2f}s then {large:.2f}s"
