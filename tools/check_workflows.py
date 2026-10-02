#!/usr/bin/env python3
"""Refuse workflow triggers that hand a fork's code our secrets, and unverified framework checkouts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.yml"))

UNSAFE_TRIGGERS = {"pull_request_target", "workflow_run"}

UNTRUSTED_REFS = ("github.event.pull_request.head.sha", "github.event.pull_request.head.ref")

FRAMEWORK_REF = re.compile(r"framework[_-]?ref", re.IGNORECASE)
PINS = {"${{ env.FRAMEWORK_REF }}", "${{ inputs.framework_ref }}"}
TOOL = "python3 tools/framework_ref.py"
BRANCH = re.compile(r"[A-Za-z0-9._/-]+")


def _triggers(workflow: dict) -> set:
    triggers = workflow.get(True) or workflow.get("on") or {}
    return set(triggers) if isinstance(triggers, dict | list) else {triggers}


def _run(step: dict) -> str:
    return str(step.get("run", "")).strip()


def _pin(step: dict) -> str:
    """The FRAMEWORK_REF a run step sees: its own env entry, else the job env the read step exported."""
    return str((step.get("env") or {}).get("FRAMEWORK_REF", "${{ env.FRAMEWORK_REF }}"))


def _validated(steps: list[dict], ref: str) -> bool:
    if ref == "${{ env.FRAMEWORK_REF }}" and any(_run(s) == f"{TOOL} read" for s in steps):
        return True
    return any(_run(s) == f"{TOOL} check" and _pin(s) == ref for s in steps)


def _verify_problem(step: dict | None, ref: str, path: str) -> str | None:
    if step is None or _run(step) != f"{TOOL} verify {path}":
        return f"the next step is not `{TOOL} verify {path}`"
    if "if" in step or "continue-on-error" in step:
        return "the verify step after it can be skipped (`if:`/`continue-on-error:`)"
    if _pin(step) != ref:
        return f"the verify step checks FRAMEWORK_REF={_pin(step)}, not the ref checked out"
    return None


def _checkout_problems(steps: list[dict], index: int) -> list[str]:
    params = steps[index].get("with") or {}
    ref, path = str(params.get("ref", "")), str(params.get("path", "."))
    if ref not in PINS:
        return [f"its ref must be one of {sorted(PINS)}"]
    problems = []
    if not _validated(steps[:index], ref):
        problems.append(f"no earlier step refuses a non-SHA ref (`{TOOL} read`, or `{TOOL} check` given it in env)")
    follower = steps[index + 1] if index + 1 < len(steps) else None
    if problem := _verify_problem(follower, ref, path):
        problems.append(problem)
    return problems


def framework_checkouts(name: str, workflow: dict) -> list[str]:
    """A checkout by FRAMEWORK_REF is validated before it and proven to be that commit right after it.

    A checkout of another repository at anything else must name a literal branch, which reads as mutable.
    """
    problems = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        steps = job.get("steps") or []
        for index, step in enumerate(steps):
            params = step.get("with") or {}
            ref = str(params.get("ref", ""))
            if not str(step.get("uses", "")).startswith("actions/checkout@"):
                continue
            where = f"{name} job {job_id!r} checks out {ref or 'the default ref'}"
            if FRAMEWORK_REF.search(ref):
                problems += [f"{where}: {p}" for p in _checkout_problems(steps, index)]
            elif "repository" in params and not BRANCH.fullmatch(ref):
                problems.append(f"{where} of {params['repository']}: pin it by FRAMEWORK_REF or name a literal branch")
    return problems


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)

    problems = []
    unsafe = _triggers(workflow) & UNSAFE_TRIGGERS
    if unsafe:
        problems.append(
            f"{path.name} triggers on {sorted(unsafe)}, which runs with this repository's "
            f"secrets against contributor-controlled input. Use `pull_request`."
        )
    problems += [
        f"{path.name} checks out {ref}, which a contributor controls." for ref in UNTRUSTED_REFS if ref in text
    ]
    return problems + framework_checkouts(path.name, workflow)


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
