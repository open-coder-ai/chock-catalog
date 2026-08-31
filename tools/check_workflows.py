#!/usr/bin/env python3
"""Refuse workflow triggers that hand a fork's code this repository's secrets."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.yml"))

UNSAFE_TRIGGERS = {"pull_request_target", "workflow_run"}

UNTRUSTED_REFS = ("github.event.pull_request.head.sha", "github.event.pull_request.head.ref")


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)

    triggers = workflow.get(True) or workflow.get("on") or {}
    if isinstance(triggers, dict):
        names = set(triggers)
    elif isinstance(triggers, list):
        names = set(triggers)
    else:
        names = {triggers}

    problems = []
    unsafe = names & UNSAFE_TRIGGERS
    if unsafe:
        problems.append(
            f"{path.name} triggers on {sorted(unsafe)}, which runs with this repository's "
            f"secrets against contributor-controlled input. Use `pull_request`."
        )
    problems += [f"{path.name} checks out {ref}, which a contributor controls." for ref in UNTRUSTED_REFS if ref in text]
    return problems


def main() -> int:
    if not WORKFLOWS:
        print("No workflows found; nothing to check.", file=sys.stderr)
        return 1

    problems = [p for path in WORKFLOWS for p in check(path)]
    if problems:
        print(f"Unsafe workflow configuration ({len(problems)} problem(s)):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"Workflow triggers are safe: {len(WORKFLOWS)} workflow(s) checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
