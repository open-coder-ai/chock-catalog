"""agent-permissions-scan: at ci the base revision is the baseline; long values are keyed by their full digest."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from policies import scriptkit
from policies.permskit import CLAUDE, mod, payload, rules, sidecar

DENIED = {"permissions": {"deny": ["Read(./.env)", "Bash(curl:*)"], "allow": ["Read"]}}
SHORTER = {"permissions": {"deny": ["Bash(curl:*)"], "allow": ["Read"]}}
WAIVER = {"waive": [{"file": CLAUDE, "path": "permissions.allow", "value": "Bash"}]}
BARE = {"permissions": {"allow": ["Bash"], "deny": ["Read(./.env)", "Bash(curl:*)"]}}


def text(value: object) -> str:
    return json.dumps(value, indent=2)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*mod.AGENT_ENV, "GITHUB_BASE_REF", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def pr(tmp_path: Path) -> tuple[Path, str]:
    """A repository whose HEAD is the change under test and whose main holds the base; returns (repo, base sha)."""
    repo = scriptkit.init_repo(tmp_path / "r", {CLAUDE: text(DENIED)})
    base = scriptkit.git_out(repo, "rev-parse", "HEAD")
    scriptkit.git(repo, "update-ref", "refs/remotes/origin/main", base)
    scriptkit.write(repo, {CLAUDE: text(SHORTER)})
    scriptkit.git(repo, "commit", "-qam", "change")
    return repo, base


def test_ci_with_a_named_base_ref_flags_a_removed_deny(pr: tuple[Path, str], monkeypatch: pytest.MonkeyPatch) -> None:
    repo, _ = pr
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    found = mod.findings(payload(repo, {CLAUDE: text(SHORTER)}, "ci"))
    assert any(f["key"].startswith("ap-deny-removed|") and "Read(./.env)" in f["key"] for f in found)


def test_ci_with_a_base_in_the_payload_flags_a_removed_deny(pr: tuple[Path, str]) -> None:
    repo, base = pr
    found = mod.findings(payload(repo, {CLAUDE: text(SHORTER)}, "ci", base=base))
    assert any(f["key"].startswith("ap-deny-removed|") for f in found)


def test_ci_with_a_push_before_flags_a_removed_deny(
    pr: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = pr
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": base}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert any(k.startswith("ap-deny-removed|") for k in _keys(repo))


def _keys(repo: Path, **extra: object) -> list[str]:
    return [f["key"] for f in mod.findings(payload(repo, {CLAUDE: text(SHORTER)}, "ci", **extra))]


def test_ci_keeping_every_deny_is_clean(pr: tuple[Path, str]) -> None:
    repo, base = pr
    assert mod.findings(payload(repo, {CLAUDE: text(DENIED)}, "ci", base=base)) == []


def test_ci_without_a_base_refuses_a_config(pr: tuple[Path, str]) -> None:
    repo, _ = pr
    assert any(k.startswith("ap-no-base|") for k in _keys(repo))


def test_ci_with_an_unresolvable_base_refuses(pr: tuple[Path, str], monkeypatch: pytest.MonkeyPatch) -> None:
    repo, _ = pr
    monkeypatch.setenv("GITHUB_BASE_REF", "gone")
    assert any(k.startswith("ap-no-base|") for k in _keys(repo))
    assert any(k.startswith("ap-no-base|") for k in _keys(repo, base="--upload-pack=x"))


def test_ci_without_a_base_ignores_unrelated_writes(pr: tuple[Path, str]) -> None:
    repo, _ = pr
    assert mod.findings(payload(repo, {"notes.txt": "x"}, "ci")) == []


def test_ci_does_not_honour_a_waiver_the_change_adds(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "w", {CLAUDE: text(DENIED)})
    base = scriptkit.git_out(repo, "rev-parse", "HEAD")
    scriptkit.write(repo, {CLAUDE: text(BARE), sidecar.PATH: text(WAIVER)})
    scriptkit.git(repo, "add", "-A")
    scriptkit.git(repo, "commit", "-qm", "change")
    writes = {CLAUDE: text(BARE), sidecar.PATH: text(WAIVER)}
    keys = [f["key"] for f in mod.findings(payload(repo, writes, "ci", base=base))]
    assert any(k.startswith("ap-agent-waiver|") for k in keys)
    assert any(k.startswith("ap-allow") or "permissions.allow" in k for k in keys)


def test_ci_honours_a_waiver_the_base_already_holds(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "h", {CLAUDE: text(DENIED), sidecar.PATH: text(WAIVER)})
    base = scriptkit.git_out(repo, "rev-parse", "HEAD")
    keys = [f["key"] for f in mod.findings(payload(repo, {CLAUDE: text(BARE)}, "ci", base=base))]
    assert not any("permissions.allow" in k for k in keys)


# --- long values are keyed by their full digest ----------------------------------------------------------------


def test_a_long_value_key_carries_the_full_digest() -> None:
    key = rules.norm("a" * 200)
    assert re.fullmatch(r"a{160}\.\.\.#[0-9a-f]{64}", key)


def test_the_gate_digest_is_the_full_digest() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", mod.digest("x"))


def test_a_missing_git_leaves_the_base_unnamed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_git(*_a: object, **_k: object) -> None:
        raise OSError

    monkeypatch.setattr(mod.base.subprocess, "run", no_git)
    assert mod.base.ci_base(tmp_path, {"base": "main"}) is None
