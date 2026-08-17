#!/usr/bin/env python3
"""Fail if the README's counts, eval numbers, or links have drifted from the repo.

A README is the first thing an adopter reads and the last thing anyone updates. The numbers
in this one -- how many policies, how many enforce, how many eval cases pass -- are exactly
the claims that would embarrass a project about not overstating enforcement.

Usage:  python tools/check_readme.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

from trees import policy_dirs

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def classify() -> tuple[dict[str, list[str]], dict[str, tuple[int, int]]]:
    kinds: dict[str, list[str]] = {"gate": [], "guard": [], "text": []}
    evals: dict[str, tuple[int, int]] = {}
    for d in policy_dirs():
        manifest = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
        gate = (manifest.get("hook") or {}).get("gate") or {}
        impl = d / "implementations"
        if gate.get("kind"):
            kinds["gate"].append(manifest["id"])
        elif impl.is_dir() and any(impl.glob("*.sh")):
            kinds["guard"].append(manifest["id"])
        else:
            kinds["text"].append(manifest["id"])

        cases = []
        suite = d / "evals" / "suite.yaml"
        if suite.exists():
            loaded = yaml.safe_load(suite.read_text(encoding="utf-8")) or {}
            block = loaded.get("suite") or loaded.get("eval_suite") or {}
            cases = block.get("cases") or block.get("test_cases") or []
        evals[manifest["id"]] = (sum(1 for c in cases if c.get("execute")), len(cases))
    return kinds, evals


def main() -> int:
    text = README.read_text(encoding="utf-8")
    kinds, evals = classify()
    total = sum(len(v) for v in kinds.values())
    enforced = len(kinds["gate"]) + len(kinds["guard"])
    problems: list[str] = []

    for label, actual, pattern in (
        ("policy count", total, r"badge/policies-(\d+)-"),
        ("enforced count", enforced, r"badge/enforced-(\d+)-"),
        ("advisory count", len(kinds["text"]), r"badge/advisory-(\d+)-"),
    ):
        found = re.search(pattern, text)
        if not found:
            problems.append(f"{label}: badge missing from README")
        elif int(found.group(1)) != actual:
            problems.append(f"{label}: README says {found.group(1)}, repo has {actual}")

    for row, want in (("enforced-at-commit", len(kinds["gate"])), ("`enforced`", len(kinds["guard"]))):
        found = re.search(rf"\| `?{re.escape(row.strip('`'))}`? \|[^|]*\|\s*(\d+) \|", text)
        if found and int(found.group(1)) != want:
            problems.append(f"ladder row {row}: README says {found.group(1)}, repo has {want}")

    for policy_id, (executed, count) in evals.items():
        found = re.search(rf"`{re.escape(policy_id)}`\]\([^)]*\)[^|]*\|[^|]*\|\s*(\d+)/(\d+)\s*\|", text)
        if found and (int(found.group(1)), int(found.group(2))) != (executed, count):
            problems.append(
                f"{policy_id}: README says {found.group(1)}/{found.group(2)}, suite has {executed}/{count}"
            )

    for link in re.findall(r"\]\((docs/[^)#]*)\)", text):
        if not (ROOT / link).exists():
            problems.append(f"broken link: {link}")

    for src in re.findall(r'src="(docs/[^"]+)"', text):
        if not (ROOT / src).exists():
            problems.append(f"missing image: {src}")

    # Every policy directory must be reachable from the README.
    for policy_id in sorted(sum(kinds.values(), [])):
        if f"`{policy_id}`" not in text:
            problems.append(f"{policy_id} is published but not mentioned in the README")

    if problems:
        print("README does not match the repo:")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"README matches: {total} policies, {enforced} enforced, {len(kinds['text'])} advisory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
