"""verify-dependency-exists: the script gate that judges every written manifest and lockfile against the allowlist."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from policies import depkit, gatekit, scriptkit

POLICY = "verify-dependency-exists"
NAME = "dependency-manifests.py"
mod, _ = depkit.load()
ALLOWLIST = ".chock/dependency-allowlist.txt"


def payload(repo: Path, writes: dict[str, str], event: str = "commit", **extra: object) -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes, **extra}


def run(repo: Path, writes: dict[str, str], **extra: object) -> tuple[int, dict, str]:
    proc = scriptkit.run_script_full(POLICY, NAME, repo, json.dumps(payload(repo, writes, **extra)))
    return proc.returncode, json.loads(proc.stdout) if proc.stdout else {}, proc.stderr


def test_seed_prints_the_tracked_manifests_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = scriptkit.init_repo(
        tmp_path / "seed",
        {
            "requirements.txt": "Requests==2\nFoo_Bar\n",
            "sub/package.json": '{"dependencies": {"left-pad": "1"}}',
            "package-lock.json": '{"packages": {"node_modules/transitive": {}}}',
            "broken/Cargo.toml": "[dependencies",
            "README.md": "# not a manifest\n",
            "bin.txt": b"\xff\xfe",
            "requirements/bad.txt": b"\xff\xfe",
        },
    )
    monkeypatch.chdir(root)
    monkeypatch.setattr(sys, "argv", [NAME, "--seed"])
    assert mod.main() == 0
    out, err = capsys.readouterr()
    assert out.splitlines() == [
        "# Seeded from the tracked manifests; review before committing.",
        "foo-bar",
        "left-pad",
        "requests",
    ]
    assert "broken/Cargo.toml skipped (TOMLDecodeError)" in err
    assert "requirements/bad.txt skipped (UnreadableError)" in err


def test_the_seed_command_runs_as_a_process_and_its_output_is_a_working_allowlist(tmp_path: Path) -> None:
    root = scriptkit.init_repo(
        tmp_path / "seed", {"requirements.txt": "requests\nflask\n", "go.mod": "require example.com/x v1\n"}
    )
    proc = scriptkit.run_script_full(POLICY, NAME, root, "")
    assert proc.returncode == 2  # no payload on stdin
    seeded = subprocess.run(
        [sys.executable, str(scriptkit.script_path(POLICY, NAME)), "--seed"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    (root / ".chock").mkdir()
    (root / ALLOWLIST).write_text(seeded.stdout, encoding="utf-8")
    assert run(root, {"requirements.txt": "requests\nflask\n", "go.mod": "require example.com/x v1\n"})[:2] == (
        0,
        {"findings": []},
    )
    assert run(root, {"requirements.txt": "requests\nfresh\n"})[0] == 1


# Through chock's own runner: the baseline run, the three events and the verdict word.
def engine(repo: Path, event: str, writes: dict[str, str]) -> tuple[int, str]:
    return gatekit.judge(POLICY, repo, event, writes)


@pytest.fixture
def engine_repo(tmp_path: Path) -> Path:
    files = {
        ALLOWLIST: "requests\n",
        "requirements.txt": "requests\nlegacy-unlisted\n",
        "package-lock.json": '{"packages": {"node_modules/requests": {}}}',
    }
    return scriptkit.init_repo(tmp_path / "engine", files)


def test_the_engine_keeps_only_what_the_change_adds(engine_repo: Path) -> None:
    same = engine(engine_repo, gatekit.PRE_TOOL_USE, {"requirements.txt": "legacy-unlisted\nrequests\n# note\n"})
    assert same == (0, "")
    added = engine(engine_repo, gatekit.PRE_TOOL_USE, {"requirements.txt": "requests\nlegacy-unlisted\nreqeusts\n"})
    assert added[0] == 1
    assert "reqeusts" in added[1]
    assert "legacy-unlisted" not in added[1]


def test_the_engine_turns_a_lockfile_only_addition_into_an_ask(engine_repo: Path) -> None:
    lock = '{"packages": {"node_modules/requests": {}, "node_modules/evil-transitive": {}}}'
    code, err = engine(engine_repo, gatekit.PRE_TOOL_USE, {"package-lock.json": lock})
    assert code != 0
    assert "evil-transitive" in err
    both = engine(
        engine_repo,
        gatekit.PRE_TOOL_USE,
        {"package-lock.json": lock, "requirements.txt": "requests\nlegacy-unlisted\nnew-one\n"},
    )
    assert both[0] == 1
    assert "new-one" in both[1]
