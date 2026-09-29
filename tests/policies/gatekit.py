"""Run a policy's declared gate through chock's own runner at the events it covers, tool use included."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
from pathlib import Path

from chock.gate import runner
from chock.gate.build import build_gate_json
from trees import ROOT, TREES

PRE_TOOL_USE = "pre-tool-use"
STOP = "stop"
COMMIT = "pre-commit"


def policy_dir(policy: str) -> Path:
    """The folder of a published policy, in whichever tree holds it."""
    return next(ROOT / tree / policy for tree in TREES if (ROOT / tree / policy).is_dir())


def gate_spec(policy: str) -> dict:
    """The compiled shape of the policy's `hook.gate`, built from its manifest."""
    spec = build_gate_json(policy_dir(policy), ROOT)
    assert spec is not None, f"{policy} declares no hook.gate"
    return spec


def judge(
    policy: str,
    repo: Path,
    event: str,
    writes: dict[str, str] | None = None,
    added: dict[str, str] | None = None,
) -> tuple[int, str]:
    """(exit code, stderr) of the gate at `event` in `repo`; a script gate's program is installed as sync does."""
    spec = gate_spec(policy)
    if spec["kind"] == "script":
        source = policy_dir(policy) / "implementations"
        shutil.copytree(source, repo / Path(spec["params"]["script"]).parent, dirs_exist_ok=True)
    gate_path = repo.parent / f"{policy}-gate.json"
    gate_path.write_text(json.dumps(spec), encoding="utf-8")
    captured = io.StringIO()
    previous = os.environ.get(runner.GATE_LOG_ENV)
    os.environ[runner.GATE_LOG_ENV] = "0"
    try:
        with contextlib.redirect_stderr(captured):
            if event in runner.AGENT_EVENTS:
                code = runner.run(gate_path, event, None, repo, writes=writes or {}, added=added)
            else:
                code = runner.run(gate_path, event, None, repo)
    finally:
        if previous is None:
            os.environ.pop(runner.GATE_LOG_ENV, None)
        else:
            os.environ[runner.GATE_LOG_ENV] = previous
    return code, captured.getvalue()
