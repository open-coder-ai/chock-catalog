"""guard-deletion: bypasses and fail-open paths found by review, each pinned."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import guard_deletion_kit, scriptkit

NAME = "guard-deletion-gate.py"
with guard_deletion_kit.shipped():
    mod = scriptkit.load("guard-deletion", NAME)

API = "def handle(req):\n    if len(req.body) > MAX_BODY:\n        raise TooLarge()\n    return work(req)\n"
API_GONE = "def handle(req):\n    return work(req)\n"
MAKE = "CFLAGS += -fstack-protector-strong -O2\n"
MAKE_GONE = "CFLAGS += -O2\n"
MIDDLEWARE = "app.use(csrfProtection)\napp.use(cors())\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    files = {"src/api.py": API, "Makefile": MAKE, "src/mw.js": MIDDLEWARE, "src/keep.py": "x = 1\n"}
    return scriptkit.init_repo(tmp_path / "r", files)


def stage(repo: Path, files: dict[str, str]) -> None:
    scriptkit.write(repo, files)
    scriptkit.git(repo, "add", "-A")


def run(repo: Path, event: str, writes: dict[str, str] | None = None, env: dict[str, str] | None = None):
    payload = json.dumps({"event": event, "repo_root": str(repo), "writes": writes or {}})
    proc = scriptkit.run_script_full("guard-deletion", NAME, repo, payload, env)
    return proc.returncode, proc.stderr


def test_a_file_marked_binary_or_holding_a_nul_byte_is_still_read(repo: Path) -> None:
    scriptkit.write(repo, {".gitattributes": "*.mk -diff\n", "a.mk": MAKE})
    stage(repo, {})
    scriptkit.git(repo, "commit", "-qm", "mk")
    stage(repo, {"a.mk": MAKE_GONE})
    assert run(repo, "commit")[0] == 1
    assert run(repo, "tool_use", {"Makefile": MAKE_GONE + "\0"})[0] == 1


def test_a_pragma_an_agent_adds_is_a_finding_even_beside_a_kept_mitigation(repo: Path) -> None:
    kept = MAKE.rstrip("\n") + "  # pragma: allowlist mitigation-removal\n"
    for event, writes in (("tool_use", {"Makefile": kept}), ("agent-commit", None)):
        if writes is None:
            stage(repo, {"Makefile": kept})
        code, err = run(repo, event, writes)
        assert code == 3 and "waiver pragma" in err, event
    assert run(repo, "commit") == (0, "")  # a person's commit may add it


def test_a_guard_removed_while_moving_the_file_out_of_scope_is_still_read(repo: Path) -> None:
    scriptkit.git(repo, "mv", "src/api.py", "vendor_api.py")
    (repo / "vendor").mkdir()
    scriptkit.git(repo, "mv", "vendor_api.py", "vendor/api.py")
    stage(repo, {"vendor/api.py": API_GONE})
    code, err = run(repo, "commit")
    assert code == 3 and "src/api.py" in err


def test_an_absolute_write_path_is_judged_and_one_outside_the_repo_is_refused(repo: Path) -> None:
    scriptkit.write(repo, {"Makefile": MAKE_GONE})  # a post-write hook: disk already holds the text
    assert run(repo, "tool_use", {str(repo / "Makefile"): MAKE_GONE})[0] == 1
    code, err = run(repo, "tool_use", {"../elsewhere/x.py": "x\n"})
    assert code == 2 and "outside the repository" in err


@pytest.mark.parametrize("event", ["", "pre-commit", "Commit", "push", "agent_commit"])
def test_an_event_the_gate_does_not_judge_is_refused(repo: Path, event: str) -> None:
    code, err = run(repo, event, {"Makefile": MAKE_GONE})
    assert code == 2 and "not one this gate judges" in err


def test_a_lone_carriage_return_does_not_hide_a_change(tmp_path: Path) -> None:
    line = "s = 'a\rb'; r = get(u, verify=%s)\n"
    root = scriptkit.init_repo(tmp_path / "cr", {})
    (root / "a.py").write_bytes((line % "True").encode())
    scriptkit.git(root, "add", "-A")
    scriptkit.git(root, "commit", "-qm", "cr")
    (root / "a.py").write_bytes((line % "False").encode())
    scriptkit.git(root, "add", "-A")
    assert run(root, "commit")[0] == 1


def test_ci_reads_a_push_from_the_event_files_before_commit(repo: Path, tmp_path: Path) -> None:
    before = scriptkit.git_out(repo, "rev-parse", "HEAD")
    stage(repo, {"Makefile": MAKE_GONE})
    scriptkit.git(repo, "commit", "-qm", "one")
    stage(repo, {"src/keep.py": "x = 3\n"})
    scriptkit.git(repo, "commit", "-qm", "two")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": before}))
    env = {"GITHUB_EVENT_PATH": str(event), "PATH": scriptkit.os_path()}
    assert run(repo, "ci", env=env)[0] == 1
    assert run(repo, "ci", env={"PATH": scriptkit.os_path()})[0] == 0  # without it, only the tip commit is read


def test_running_out_of_time_asks(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mod, "BUDGET", -1.0)
    stage(repo, {"src/api.py": API_GONE})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"event": "commit", "repo_root": str(repo)})))
    assert mod.main() == 3
    assert "out of time" in capsys.readouterr().err
