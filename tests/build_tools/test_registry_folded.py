"""A label sees the guards and gates a folded `--multi` index runs, and an engine bump moves no keyword unnoticed."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from agentseam import packaging
from chock.plugin import bundle_build
from trees import ROOT, TREES

ROWS = {p["id"]: p for p in yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))["policies"]}
INDEX = re.compile(r"--multi \"?[^\" ]*?(scripts/chock_index/[^\" ]+\.json)")
ENFORCING = ("--guard", "--gate")
BASE = "origin/main"
GIT = shutil.which("git") or "git"
#: (policy, label key) -> why its keyword differs from BASE's registry.yaml. Empty: none may.
KEYWORD_CHANGES: dict[tuple[str, str], str] = {}


def _commands(node: object) -> list[str]:
    if isinstance(node, dict):
        own = [node["command"]] if isinstance(node.get("command"), str) else []
        return own + [c for value in node.values() for c in _commands(value)]
    if isinstance(node, list):
        return [c for item in node for c in _commands(item)]
    return []


def _runs(package: Path, hooks_rel: str) -> list[str]:
    """Every hook command the package ships, plus each folded index member's argv as one string."""
    hooks = package / hooks_rel
    if not hooks.is_file():
        return []
    runs = _commands(json.loads(hooks.read_text(encoding="utf-8")))
    for command in list(runs):
        if ref := INDEX.search(command):
            members = json.loads((package / ref.group(1)).read_text(encoding="utf-8"))["members"]
            runs += [" ".join(str(arg) for arg in member["argv"]) for member in members]
    return runs


@pytest.fixture(scope="module")
def claude_runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[str]]:
    """What each policy's built claude package runs, folded members included."""
    out = tmp_path_factory.mktemp("built")
    for tree in TREES:
        subprocess.run(
            [sys.executable, "-m", "chock", "plugin", "build", "--repo", str(ROOT), "--policies-dir", tree,
             "--format", "claude", "--out-dir", str(out / tree)],
            check=True, capture_output=True, text=True,
        )  # fmt: skip
    rel = packaging.supports(bundle_build.CLIENTS["claude"].package_agent, packaging.HOOKS)
    return {pid: _runs(out / Path(row["path"]).parent.name / "claude" / pid, rel) for pid, row in ROWS.items()}


def test_a_package_that_ships_a_guard_or_gate_is_not_labelled_advisory(claude_runs: dict[str, list[str]]) -> None:
    enforcing = [pid for pid, runs in claude_runs.items() if any(f in r for r in runs for f in ENFORCING)]
    assert enforcing, "no built package ships a guard or gate: the scan above is broken"
    advisory = [pid for pid in enforcing if ROWS[pid]["label"]["claude-code"]["keyword"] == "advise"]
    assert not advisory, f"{len(advisory)} of {len(enforcing)} enforcing packages labelled advise: {advisory}"


def _keywords(registry: str) -> dict[tuple[str, str], str]:
    rows = yaml.safe_load(registry)["policies"]
    return {
        (row["id"], key): cell["keyword"]
        for row in rows
        for key, cell in row["label"].items()
        if isinstance(cell, dict) and "keyword" in cell
    }


def test_the_keyword_table_matches_main_except_where_a_reason_is_named() -> None:
    shown = subprocess.run(
        [GIT, "show", f"{BASE}:registry.yaml"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if shown.returncode:
        pytest.skip(f"{BASE} is not fetched in this checkout")
    before, after = _keywords(shown.stdout), _keywords((ROOT / "registry.yaml").read_text(encoding="utf-8"))
    moved = {k: (before[k], after[k]) for k in before.keys() & after.keys() if before[k] != after[k]}
    unexplained = {k: v for k, v in sorted(moved.items()) if k not in KEYWORD_CHANGES}
    assert not unexplained, f"{len(unexplained)} keywords moved from {BASE} with no reason named: {unexplained}"
