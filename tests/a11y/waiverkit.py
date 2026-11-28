"""Shared by the waiver tests: the review's pairs staged in a throwaway repository, and the guard run as a process."""

from __future__ import annotations

import json
import os
from pathlib import Path

import check_a11y_pairs as pairs
import check_a11y_rules as rules
from policies import scriptkit

POLICY = "no-a11y-regression"
COMMIT = "no-a11y-regression-pre-commit.py"
WRITE = "no-a11y-regression-write.py"
GUARD = rules.load_guard()
SIDECAR = GUARD.SPEC["waiver"]["path"]
AGENT_ENV = GUARD.SPEC["waiver"]["agent_env"]
ASK, WARN = GUARD.SPEC["waiver"]["exit"]["ask"], GUARD.SPEC["waiver"]["exit"]["warn"]
#: Correct work the guard blocks by default, and the one new fixture it warns about.
CONFIG = ".chock/config.yaml"  # the committed file the rollout level is read from, never an environment override
DECORATIVE = ("N04", "N05", "N06", "P14")
FIXTURE = "N29"


def pair(pair_id: str) -> dict:
    return next(p for p in pairs.load_pairs() if p["id"] == pair_id)


def sidecar(waive: list[dict] | None = None, exempt: list[dict] | None = None) -> str:
    body: dict = {}
    if waive is not None:
        body["waive"] = waive
    if exempt is not None:
        body["exempt"] = exempt
    return json.dumps(body, indent=2) + "\n"


def refs(pair_id: str) -> list[tuple[str, str]]:
    """(file, element) of every finding the guard makes on a pair: what a person would waive."""
    found = []
    for path, text in pair(pair_id)["files"].items():
        for row in GUARD.evaluate(text["before"], text["after"]):
            if row["action"] in (GUARD.DENY, GUARD.WARN):
                found.append((path, row["ref"]))
    return found


def waiver_for(pair_id: str) -> str:
    return sidecar([{"file": f, "element": e, "reason": "reviewed: decorative"} for f, e in refs(pair_id)])


def staged_repo(
    tmp: Path,
    pair_id: str,
    head_sidecar: str | None = None,
    staged_sidecar: str | None = None,
    level: str | None = None,
) -> Path:
    """HEAD holds each file's `before`, the sidecar and the committed rollout level when given; the index holds `after`."""
    files = {p: t["before"] for p, t in pair(pair_id)["files"].items() if t["before"]}
    if head_sidecar is not None:
        files[SIDECAR] = head_sidecar
    if level is not None:
        files[CONFIG] = f"rollout: {level}\n"
    repo = scriptkit.init_repo(tmp / "r", files or {"keep.txt": "x\n"})
    scriptkit.write(repo, {p: t["after"] for p, t in pair(pair_id)["files"].items()})
    if staged_sidecar is not None:
        scriptkit.write(repo, {SIDECAR: staged_sidecar})
    scriptkit.git(repo, "add", "-A")
    return repo


def commit(repo: Path, *, agent: bool = False) -> tuple[int, str]:
    env = {k: v for k, v in os.environ.items() if k not in AGENT_ENV}
    if agent:
        env["CLAUDECODE"] = "1"
    return scriptkit.run_script(POLICY, COMMIT, repo, env=env)
