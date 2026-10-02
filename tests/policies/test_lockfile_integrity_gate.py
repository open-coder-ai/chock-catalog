"""lockfile-integrity: the script gate end to end -- baselines per event, verdicts, the engine and big locks."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from policies import gatekit, scriptkit
from policies.lockkit import (
    BASE_LOCK,
    BASE_MANIFEST,
    NAME,
    POLICY,
    found,
    gate,
    h,
    manifest,
    model,
    npm_lock,
    payload,
    pkg,
)

EVIL = "https://npm.evil.example/left-pad-1.3.0.tgz"
SWAPPED = npm_lock({"left-pad": pkg("left-pad", "1.3.0", resolved=EVIL)})
BUMP = manifest({"left-pad": "^1.3.0", "is-odd": "^3.0.1"})


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"package.json": BASE_MANIFEST, "package-lock.json": BASE_LOCK})


def test_the_manifest_declares_the_script_gate() -> None:
    gate_spec = scriptkit.manifest(POLICY)["hook"]["gate"]
    assert (gate_spec["kind"], gate_spec["on"], gate_spec["params"]) == (
        "script",
        ["commit", "tool_use"],
        {"script": NAME},
    )


def test_a_commit_judges_against_head_and_marks_findings_new(repo: Path) -> None:
    findings, compared = gate.judge(payload(repo, {"package.json": BUMP, "package-lock.json": SWAPPED}))
    assert compared is True
    assert [f.rule for f in findings] == [model.SOURCE]
    reformatted = json.dumps(json.loads(BASE_LOCK)) + "\n"
    assert found(repo, {"package.json": BUMP, "package-lock.json": reformatted}) == []


def test_a_replaced_hash_of_a_locked_version_is_caught_only_with_a_baseline(repo: Path) -> None:
    rehashed = npm_lock({"left-pad": pkg("left-pad", "1.3.0", "Z")})
    assert found(repo, {"package.json": BUMP, "package-lock.json": rehashed}) == [model.CHANGED]
    assert found(repo, {"package.json": BUMP, "package-lock.json": rehashed}, "ci") == []


def test_tool_use_reads_the_disk_unless_it_already_holds_the_write(repo: Path) -> None:
    (repo / "package-lock.json").write_text(SWAPPED, encoding="utf-8")
    assert found(repo, {"package-lock.json": SWAPPED}, "tool_use") == [model.SOURCE]  # disk == write: HEAD
    assert found(repo, {"package-lock.json": SWAPPED + "\n"}, "tool_use") == []  # disk is the baseline
    (repo / "package-lock.json").write_bytes(b"\xff")
    assert found(repo, {"package-lock.json": SWAPPED}, "tool_use") == [model.SOURCE]
    assert found(repo, {str(repo / "elsewhere" / "package-lock.json"): SWAPPED}, "tool_use") == [model.SOURCE]


def test_ci_and_push_report_keyed_findings_for_the_engine_baseline(repo: Path) -> None:
    findings, compared = gate.judge(payload(repo, {"package-lock.json": SWAPPED}, "ci"))
    assert compared is False
    assert sorted(f.rule for f in findings) == [model.SOURCE, model.LOCK_ONLY]


def test_the_engine_baseline_run_is_empty_where_the_change_run_compared(repo: Path) -> None:
    assert gate.judge(payload(repo, {"package-lock.json": SWAPPED}, "commit", baseline=True)) == ([], False)
    assert found(repo, {"package-lock.json": SWAPPED}, "push", baseline=True) != []


def test_a_commit_that_deletes_a_lock_asks(repo: Path) -> None:
    scriptkit.git(repo, "rm", "-q", "package-lock.json")
    assert found(repo, {"package.json": BUMP}) == [model.DELETED]
    assert found(repo, {"package.json": BUMP}, "tool_use") == []


def test_without_git_everything_is_new(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "GIT", None)
    assert found(repo, {"package.json": BASE_MANIFEST, "package-lock.json": SWAPPED}) == [model.SOURCE]
    assert gate.committed(repo, "/abs/package-lock.json") is None


def test_the_committed_allowlist_counts_and_an_unreadable_one_is_named(tmp_path: Path) -> None:
    allow = {".chock/registry-allowlist.txt": "npm.evil.example\n"}
    repo = scriptkit.init_repo(tmp_path / "a", {"package.json": BASE_MANIFEST, **allow})
    assert found(repo, {"package-lock.json": SWAPPED}, "tool_use") == []
    broken = scriptkit.init_repo(tmp_path / "b", {".chock/registry-allowlist.txt": "bad host\n"})
    findings, _ = gate.judge(payload(broken, {"package-lock.json": SWAPPED}, "tool_use"))
    assert "could not be read" in findings[0].message


def test_an_unreadable_lock_is_refused_and_files_outside_the_rules_are_ignored(repo: Path) -> None:
    assert found(repo, {"package-lock.json": "{", "notes.txt": "x"}, "tool_use") == [model.UNPARSEABLE]


@pytest.mark.parametrize("bad", [{"writes": []}, {"writes": {"a": 1}}, {}])
def test_a_malformed_payload_is_a_fault(bad: dict) -> None:
    with pytest.raises(TypeError):
        gate.judge({"event": "commit", **bad})


def run(repo: Path, body: object, *, untraced: bool = False) -> tuple[int, dict | None, str]:
    """Run the gate as the runner does; `untraced` leaves coverage out, so a timing measures the gate alone."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("COVERAGE_")} if untraced else None
    proc = scriptkit.run_script_full(POLICY, NAME, repo, json.dumps(body), env)
    try:
        document = json.loads(proc.stdout)
    except ValueError:
        document = None
    return proc.returncode, document, proc.stderr


def test_exit_codes_follow_the_highest_new_tier(repo: Path) -> None:
    code, document, err = run(repo, payload(repo, {"package.json": BUMP, "package-lock.json": SWAPPED}))
    assert code == 1
    assert document["findings"][0]["new"] is True
    assert "lock-source-host" in err
    code, _, _ = run(repo, payload(repo, {"package-lock.json": BASE_LOCK + "\n"}))
    assert code == 3
    assert run(repo, payload(repo, {"package.json": BASE_MANIFEST}))[:2] == (0, {"findings": []})
    assert run(repo, payload(repo, {"package-lock.json": SWAPPED}, "ci", baseline=True))[0] == 0
    code, document, err = run(repo, "not a payload")
    assert (code, document) == (2, None)
    assert "internal error" in err


def test_the_engine_refuses_a_swapped_host_and_holds_a_lock_moved_alone(repo: Path) -> None:
    scriptkit.write(repo, {"package.json": BUMP, "package-lock.json": SWAPPED})
    scriptkit.git(repo, "add", "-A")
    code, err = gatekit.judge(POLICY, repo, gatekit.COMMIT)
    assert code == 1
    assert "npm.evil.example" in err
    scriptkit.git(repo, "reset", "-q")
    scriptkit.write(repo, {"package.json": BASE_MANIFEST, "package-lock.json": BASE_LOCK + "\n"})
    scriptkit.git(repo, "add", "-A")
    code, err = gatekit.judge(POLICY, repo, gatekit.COMMIT)
    assert code == 1  # a git hook cannot prompt: an ask refuses unless the person names the policy in CHOCK_ALLOW
    assert "without its manifest" in err
    assert "asks a person" in err


def test_the_engine_judges_only_what_the_turn_changed(repo: Path) -> None:
    old_git = npm_lock({"old": pkg("old", "1.0.0", resolved="git+ssh://git@github.com/x/old.git", integrity=False)})
    scriptkit.write(repo, {"package-lock.json": old_git})
    scriptkit.git(repo, "commit", "-qam", "git dep")
    assert gatekit.judge(POLICY, repo, gatekit.STOP, {"package-lock.json": old_git + "\n"})[0] == 0
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {"package-lock.json": SWAPPED})[0] == 1


def test_a_huge_lockfile_is_judged_well_inside_the_budget(repo: Path) -> None:
    many = {f"pkg-{i}": pkg(f"pkg-{i}", "1.0.0", "ABCDEFGH"[i % 8]) for i in range(40_000)}
    big = npm_lock(many)
    assert len(big) > 10_000_000
    bigger = npm_lock({**many, "late": pkg("late", "1.0.0", resolved=EVIL)})
    scriptkit.write(repo, {"package-lock.json": big})
    scriptkit.git(repo, "commit", "-qam", "big")
    started = time.monotonic()
    code, document, _ = run(repo, payload(repo, {"package-lock.json": bigger}), untraced=True)
    elapsed = time.monotonic() - started
    assert code == 1
    assert [f["rule"] for f in document["findings"]] == [model.SOURCE, model.LOCK_ONLY]
    assert elapsed < 10


def test_a_huge_pnpm_lock_is_read_through_the_yaml_scanner_inside_the_budget(repo: Path) -> None:
    rows = "".join(f"  pkg-{i}@1.0.0:\n    resolution: {{integrity: {h('ABCD'[i % 4])}}}\n\n" for i in range(25_000))
    big = f"lockfileVersion: '9.0'\n\npackages:\n\n{rows}"
    assert len(big) > 3_000_000
    scriptkit.write(repo, {"pnpm-lock.yaml": big})
    scriptkit.git(repo, "add", "-A")
    scriptkit.git(repo, "commit", "-qm", "pnpm")
    late = f"  late@1.0.0:\n    resolution: {{tarball: {EVIL}}}\n"
    started = time.monotonic()
    code, document, _ = run(repo, payload(repo, {"pnpm-lock.yaml": big + late}, "tool_use"), untraced=True)
    elapsed = time.monotonic() - started
    assert code == 1
    assert [f["rule"] for f in document["findings"]] == [model.SOURCE, model.MISSING]
    assert elapsed < 15


def test_an_agent_may_not_widen_the_registry_allowlist(repo: Path) -> None:
    allow = {".chock/registry-allowlist.txt": "npm.evil.example\n"}
    assert found(repo, allow, "tool_use") == [model.ALLOWLIST_EDIT]
    assert found(repo, {"sub/.chock/Registry-Allowlist.txt": "x\n"}, "agent-commit") == [model.ALLOWLIST_EDIT]
    assert found(repo, allow, "commit") == []  # a person's commit
    scriptkit.write(repo, allow)
    scriptkit.git(repo, "add", "-A")
    scriptkit.git(repo, "commit", "-qm", "reviewed host")
    assert found(repo, allow, "tool_use") == []  # unchanged from HEAD
