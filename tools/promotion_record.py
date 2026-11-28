"""What a promotion record adds to a replay: the policy's own eval cases run by the framework, and its Misses sentence."""

from __future__ import annotations

import re
from pathlib import Path

from chock.eval.execute import run_case
from chock.eval.suites import Policy, load_cases
from chock.manifest import load_manifest


def misses_listed(description: str) -> int:
    """The items the description's own `Misses:` sentence names, split on commas outside parentheses; 0 with none."""
    tail = " ".join(description.split()).partition("Misses: ")[2]
    sentence = re.match(r"(?:[^.(]|\.(?=\S)|\([^)]*\))*", tail).group()
    return len(re.split(r",\s*(?![^()]*\))", sentence)) if sentence.strip() else 0


def eval_counts(root: Path, folder: Path) -> dict:
    """Each authored executable case replayed: refusing cases caught (`block`), allowing cases allowed (`allow`)."""
    guards = Policy(folder.name, folder, load_manifest(folder)[0]).guards
    counts = {"block": {"caught": 0, "total": 0}, "allow": {"allowed": 0, "total": 0}}
    for case in load_cases(folder, folder.name):
        if case.execute:
            side, hit = ("allow", "allowed") if case.execute.get("expect", "block") == "allow" else ("block", "caught")
            counts[side]["total"] += 1
            counts[side][hit] += run_case(case, folder, root, guards).outcome == "pass"
    return counts
