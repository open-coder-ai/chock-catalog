#!/usr/bin/env python3
"""Refuse workflow triggers that hand a fork's code our secrets, and unverified framework checkouts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"
WORKFLOWS = sorted([*_DIR.glob("*.yml"), *_DIR.glob("*.yaml")])

UNSAFE_TRIGGERS = {"pull_request_target", "workflow_run"}

UNTRUSTED_REFS = ("github.event.pull_request.head.sha", "github.event.pull_request.head.ref")

FRAMEWORK_REF = re.compile(r"framework[_-]?ref", re.IGNORECASE)
PINS = {"${{ env.FRAMEWORK_REF }}", "${{ inputs.framework_ref }}"}
TOOL = "python3 tools/framework_ref.py"
BRANCH = re.compile(r"[A-Za-z0-9._/-]+")
HEXISH = re.compile(r"[0-9a-fA-F]{7,64}")
# A verify step is its command and the ref it checks: shell, working-directory or extra env could neuter it.
VERIFY_KEYS = {"name", "id", "run", "env"}


def _triggers(workflow: dict) -> set:
    triggers = workflow.get(True) or workflow.get("on") or {}
    return set(triggers) if isinstance(triggers, dict | list) else {triggers}


def _run(step: dict) -> str:
    return str(step.get("run", "")).strip()


def _params(step: dict) -> dict:
    """Action inputs are case-insensitive at runtime (INPUT_REF), so match them that way."""
    return {str(k).lower(): v for k, v in (step.get("with") or {}).items()}


def _is_checkout(step: dict) -> bool:
    return str(step.get("uses", "")).lower().startswith("actions/checkout@")


def _pin(step: dict) -> str:
    """The FRAMEWORK_REF a run step sees: its own env entry, else the job env the read step exported."""
    return str((step.get("env") or {}).get("FRAMEWORK_REF", "${{ env.FRAMEWORK_REF }}"))


def _skippable(step: dict) -> bool:
    return "if" in step or "continue-on-error" in step


def _validated(steps: list[dict], ref: str) -> bool:
    for step in steps:
        if _skippable(step):
            continue
        if ref == "${{ env.FRAMEWORK_REF }}" and _run(step) == f"{TOOL} read":
            return True
        if _run(step) == f"{TOOL} check" and _pin(step) == ref:
            return True
    return False


def _verify_problem(step: dict | None, ref: str, path: str) -> str | None:
    if step is None or _run(step) != f"{TOOL} verify {path}":
        return f"the next step is not `{TOOL} verify {path}`"
    if _skippable(step):
        return "the verify step after it can be skipped (`if:`/`continue-on-error:`)"
    if extra := sorted(set(step) - VERIFY_KEYS) + sorted(set(step.get("env") or {}) - {"FRAMEWORK_REF"}):
        return f"the verify step after it sets {extra}, which can change what it runs or checks"
    if _pin(step) != ref:
        return f"the verify step checks FRAMEWORK_REF={_pin(step)}, not the ref checked out"
    return None


def _checkout_problems(steps: list[dict], index: int) -> list[str]:
    params = _params(steps[index])
    ref, path = str(params.get("ref", "")), str(params.get("path", "."))
    if ref not in PINS:
        return [f"its ref must be one of {sorted(PINS)}"]
    problems = []
    if str(params.get("clean", True)).lower() == "false":
        problems.append("`clean: false` keeps files the pinned commit does not have")
    if not _validated(steps[:index], ref):
        problems.append(f"no earlier step refuses a non-SHA ref (`{TOOL} read`, or `{TOOL} check` given it in env)")
    follower = steps[index + 1] if index + 1 < len(steps) else None
    if problem := _verify_problem(follower, ref, path):
        problems.append(problem)
    return problems


def framework_checkouts(name: str, workflow: dict) -> list[str]:
    """A checkout by FRAMEWORK_REF is validated before it and its HEAD proven to be that commit right after.

    A checkout of another repository at anything else must name a literal, non-hex branch, which reads as
    mutable. Not seen: steps after the verify step, composite actions, reusable workflows, `run: git clone`.
    """
    problems = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        steps = job.get("steps") or []
        for index, step in enumerate(steps):
            if not _is_checkout(step):
                continue
            params = _params(step)
            ref = str(params.get("ref", ""))
            where = f"{name} job {job_id!r} checks out {ref or 'the default ref'}"
            if FRAMEWORK_REF.search(ref):
                problems += [f"{where}: {p}" for p in _checkout_problems(steps, index)]
                if (workflow.get("defaults") or {}).get("run") or (job.get("defaults") or {}).get("run"):
                    problems.append(f"{where}: `defaults.run` can change the shell or directory its verify runs in")
            elif "repository" in params and (not BRANCH.fullmatch(ref) or HEXISH.fullmatch(ref)):
                problems.append(
                    f"{where} of {params['repository']}: a pin goes through FRAMEWORK_REF and its verify step; "
                    "otherwise name a literal branch, which reads as mutable"
                )
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
