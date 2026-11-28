#!/usr/bin/env python3
"""Replay the hardening review's infra cases through the engine's replay path and count both directions on main."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

from chock.eval import execute
from chock.eval.fixture import git, init_repo, prepare, write_files
from chock.eval.model import Case
from chock.eval.suites import Policy
from chock.gate import runner as gate_runner
from chock.manifest import load_manifest
from trees import ROOT

FIXTURES = Path(__file__).resolve().parent / "infra_fixtures"
#: Fixture file stem -> the policy folder it measures.
POLICIES = {
    "block-wildcard-iam": "agentic-security/block-wildcard-iam",
    "iam-policy-scan": "agentic-security/iam-policy-scan",
    "protect-ci-workflows": "base/protect-ci-workflows",
    "dockerfile-compose-security": "base/dockerfile-compose-security",
}
REFUSED = ("block", "ask")
#: Surfaces the replay can drive; `command` cases run the policy's shell guard.
SURFACES = ("commit", "tool_use", "stop", "agent-commit", "ci")
_AGENT_MARKER = {gate_runner.CLAUDECODE_ENV: "1"}


def load(policy: str) -> dict[str, Any]:
    """The fixture file of one policy: its cases and the ones that could not be rebuilt."""
    return json.loads((FIXTURES / f"{policy}.json").read_text(encoding="utf-8"))


def load_cases(policy: str) -> list[dict]:
    return load(policy)["cases"]


@contextlib.contextmanager
def _agent_env() -> Iterator[None]:
    """Judge a commit as an agent's: the agent marker set, every other override cleared."""
    names = (gate_runner.AGENT_COMMIT_ENV, gate_runner.CLAUDECODE_ENV, gate_runner.AI_AGENT_ENV, gate_runner.ALLOW_ENV)
    saved = {n: os.environ.pop(n) for n in names if n in os.environ}
    os.environ.update(_AGENT_MARKER)
    try:
        yield
    finally:
        os.environ.pop(gate_runner.CLAUDECODE_ENV, None)
        os.environ.update(saved)


def _spec(case: dict) -> dict[str, Any]:
    """The replay spec of a case: `before` is HEAD, `after` is the change, `repo_files` stays unstaged."""
    event = {"agent-commit": "commit", "ci": "commit"}.get(case["surface"], case["surface"])
    spec: dict[str, Any] = {"event": event}
    if "command" in case:
        spec["event"] = "tool_use"
        spec["command"] = case["command"]
        return spec
    files = case.get("files", {})
    spec["head_files"] = {p: t["before"] for p, t in files.items() if t.get("before")}
    spec["files"] = {p: t["after"] for p, t in files.items() if t.get("after") is not None}
    spec["repo_files"] = case.get("repo_files", {})
    return spec


def _ci(repo: Path, policy_dir: Path, spec: dict[str, Any]) -> tuple[str, str]:
    """Commit the change in the throwaway repository and judge it as CI does, against HEAD~1."""
    gate_spec, _ = execute.resolve_gate(policy_dir, ROOT)
    prepare(repo, spec)
    execute._install_script(repo, policy_dir, gate_spec)
    git(repo, "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "change")
    gate_path = repo / "gate.json"
    gate_path.write_text(json.dumps(gate_spec), encoding="utf-8", newline="\n")
    os.environ[gate_runner.GATE_LOG_ENV] = "0"
    with execute._person_env():
        code, judged = gate_runner.judge(gate_path, "ci", None, repo, base="HEAD~1")
    return execute._observed(code, judged), f"exit {code}"


def verdict(policy: str, case: dict) -> tuple[str, str]:
    """(verdict, detail) of one case on this checkout's policy, by the engine's own replay."""
    policy_dir = ROOT / POLICIES[policy]
    loaded = load_manifest(policy_dir)
    guards = Policy(policy_dir.name, policy_dir, loaded[0]).guards
    spec = _spec(case)
    with tempfile.TemporaryDirectory(prefix="infra-pairs-") as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        if case["surface"] == "ci":
            return _ci(repo, policy_dir, spec)
        if "command" in case:
            init_repo(repo)
            write_files(repo, case.get("repo_files", {}))
            return execute._run_guard(repo, guards[0], case["command"])
        run = Case(case["id"], "pair", case["title"], "-", policy, execute=spec)
        if case["surface"] == "agent-commit":
            saved = execute._person_env
            execute._person_env = _agent_env
            try:
                return execute._replay(run, spec, (repo, policy_dir, ROOT, guards))
            finally:
                execute._person_env = saved
        return execute._replay(run, spec, (repo, policy_dir, ROOT, guards))


def measure(policy: str) -> dict[str, Any]:
    """Counts per direction and the ids behind them, with the observed verdict of every case."""
    cases = load_cases(policy)
    seen = {c["id"]: (c, *verdict(policy, c)) for c in cases}
    catch = [i for i, (c, *_) in seen.items() if c["kind"] == "catch"]
    correct = [i for i, (c, *_) in seen.items() if c["kind"] == "correct"]
    probes = [i for i, (c, *_) in seen.items() if c["kind"] == "probe"]
    return {
        "seen": seen,
        "catch": catch,
        "correct": correct,
        "probes": probes,
        "caught": [i for i in catch if seen[i][1] in REFUSED],
        "missed": [i for i in catch if seen[i][1] not in REFUSED],
        "refused": [i for i in correct if seen[i][1] in REFUSED],
    }


def check(policy: str, m: dict[str, Any]) -> list[str]:
    """Every case whose observed verdict differs from its `expect`."""
    return [
        f"{policy} {i}: observed {v} ({detail[:80]}), expected {c['expect']}"
        for i, (c, v, detail) in m["seen"].items()
        if v != c["expect"]
    ]


def main() -> int:
    failures: list[str] = []
    for policy in POLICIES:
        m = measure(policy)
        print(
            f"{policy}: caught {len(m['caught'])} of {len(m['catch'])}; correct work refused "
            f"{len(m['refused'])} of {len(m['correct'])}; probes {len(m['probes'])}; "
            f"unrebuilt {len(load(policy)['unrebuilt'])}"
        )
        print(f"  missed: {' '.join(m['missed'])}")
        print(f"  refused: {' '.join(m['refused'])}")
        failures += check(policy, m)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
