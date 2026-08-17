#!/usr/bin/env python3
"""Refuse workflow triggers that hand a fork's code this repository's secrets.

`pull_request_target` runs with the *base* repository's token and secrets while checking out
whatever the pull request asks for. On a public repo that is one careless `ref:` away from
giving a stranger's branch a write-scoped `GITHUB_TOKEN` -- the standard way a public
repository with CI automation gets compromised.

This repo has a specific reason to care. It distributes executable content: `implementations/*.sh`
becomes a git hook on every commit in an adopter's repository. A compromised workflow here does
not just leak a token, it can publish a malicious guard script to everyone who runs
`chock add`.

The workflow is clean today -- it triggers on `push` and `pull_request`. The temptation arrives
the first time someone wants a bot to label or comment on a fork PR, because `pull_request`
cannot reach secrets and `pull_request_target` can. That is exactly the moment nobody is
thinking about the token, which is why this is a check rather than a convention.

The framework repo enforces the same rule in `tests/test_workflow_safety.py`. Duplicated
deliberately: the two repos ship separately, and a control that lives only in the other one is
not a control here.

Usage:  python tools/check_workflows.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.yml"))

#: Triggers that run with the base repo's secrets against contributor-controlled input.
UNSAFE_TRIGGERS = {"pull_request_target", "workflow_run"}

#: Refs a pull request controls. Harmless under `pull_request`, which is already unprivileged,
#: but checked so that a later trigger change cannot arm them silently.
UNTRUSTED_REFS = ("github.event.pull_request.head.sha", "github.event.pull_request.head.ref")


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)

    # `on:` is the YAML 1.1 boolean true, and PyYAML parses it as such. Looking only for the
    # string "on" finds nothing and passes every file -- a checker that cannot fail.
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
