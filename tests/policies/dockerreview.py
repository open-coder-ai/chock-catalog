"""Shared by the dockerfile-compose-security review tests: case text pieces, the baseline rule and the runner."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
from collections import Counter
from pathlib import Path

from chock.gate import runner
from policies import dockerkit, gatekit

POLICY = "dockerfile-compose-security"
mod = dockerkit.load()
person = dockerkit.person

from dkscan.rules import DENY, RULES  # noqa: E402

PIN = "@sha256:" + "0" * 64
BASE = f"FROM alpine:3.20{PIN}\n"
IMG = f"example/app:1.0{PIN}"
LONG = "# " + "x" * 78 + "\n"
SUM = "0" * 64
SHA = "0" * 40
LEGACY_DOCKERFILE = "FROM ubuntu:latest\nRUN curl -fsSL https://example.com/i.sh | sh\n"
LEGACY_COMPOSE = 'services:\n  cache:\n    image: redis:latest\n    privileged: true\n    ports:\n      - "6379:6379"\n'


def compose(body: str, image: str = IMG, name: str = "app") -> str:
    return f"services:\n  {name}:\n    image: {image}\n{body}"


def judged(head: dict[str, str] | None, writes: dict[str, str], event: str = "commit") -> tuple[str, set[str]]:
    """(verdict, rules) of what `writes` add over `head`; a path with no HEAD copy has no baseline."""
    base = {"repo_root": dockerkit.BARE, "event": event}
    found = mod.findings({**base, "writes": writes})
    spent: Counter = Counter()
    for path, text in (head or {}).items():
        if path in writes:
            spent.update(
                (f["path"], f["key"]) for f in mod.findings({**base, "writes": {path: text}, "baseline": True})
            )
    fresh = []
    for item in found:
        slot = (item["path"], item["key"])
        if item.get("new") or not spent[slot]:
            fresh.append(item)
        else:
            spent[slot] -= 1
    rules = {item["rule"] for item in fresh}
    if not rules:
        return "allow", rules
    return ("block" if any(RULES[rule].tier == DENY for rule in rules) else "ask"), rules


def engine(repo: Path, event: str, base: str | None = None) -> int:
    """The runner's exit code for the policy's gate at `event` (pre-commit or ci) in `repo`."""
    spec = gatekit.gate_spec(POLICY)
    shutil.copytree(
        gatekit.policy_dir(POLICY) / "implementations", repo / Path(spec["params"]["script"]).parent, dirs_exist_ok=True
    )
    gate_path = repo.parent / "gate.json"
    gate_path.write_text(json.dumps(spec), encoding="utf-8")
    gatekit._head_forget()
    previous = os.environ.get(runner.GATE_LOG_ENV)
    os.environ[runner.GATE_LOG_ENV] = "0"
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return runner.run(gate_path, event, None, repo, base=base)
    finally:
        if previous is None:
            os.environ.pop(runner.GATE_LOG_ENV, None)
        else:
            os.environ[runner.GATE_LOG_ENV] = previous
