"""guard-deletion: the script gate over a staged change, a CI range and an agent's writes, run on real repositories."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import gatekit, guard_deletion_kit, scriptkit

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


def test_a_staged_guard_removal_asks_and_names_the_file_and_family(repo: Path) -> None:
    stage(repo, {"src/api.py": API_GONE})
    code, err = run(repo, "commit")
    assert code == 3
    assert "src/api.py:" in err and "length, size or count" in err and "mitigation-removal" not in err.split("Keep")[0]


def test_a_staged_mitigation_removal_blocks(repo: Path) -> None:
    stage(repo, {"Makefile": MAKE_GONE})
    code, err = run(repo, "commit")
    assert code == 1
    assert "Makefile:1" in err and "stack protector" in err and "-fstack-protector-strong" in err


def test_both_rules_in_one_change_report_both_and_block(repo: Path) -> None:
    stage(repo, {"src/api.py": API_GONE, "Makefile": MAKE_GONE})
    code, err = run(repo, "commit")
    assert code == 1
    assert "mitigation-removal:" in err and "guard-deletion:" in err


def test_a_refactored_check_a_rename_and_a_new_file_are_silent(repo: Path) -> None:
    refactor = API.replace("len(req.body) > MAX_BODY", "req.size > LIMIT")
    stage(repo, {"src/api.py": refactor, "src/new.py": "def f():\n    if len(x) > 1:\n        raise E\n"})
    assert run(repo, "commit") == (0, "")
    scriptkit.git(repo, "commit", "-q", "-m", "refactor")
    scriptkit.git(repo, "mv", "src/api.py", "src/handler.py")
    assert run(repo, "commit") == (0, "")


def test_deleting_a_middleware_module_asks_when_the_commit_also_changes_a_file(repo: Path) -> None:
    scriptkit.git(repo, "rm", "-q", "src/mw.js")
    stage(repo, {"src/keep.py": "x = 2\n"})
    code, err = run(repo, "commit")
    assert (code, "src/mw.js" in err) == (3, True)


def test_a_crlf_file_is_judged_like_an_lf_file(tmp_path: Path) -> None:
    crlf = scriptkit.init_repo(tmp_path / "c", {})
    scriptkit.git(crlf, "config", "core.autocrlf", "false")
    (crlf / "a.py").write_bytes(API.replace("\n", "\r\n").encode())
    scriptkit.git(crlf, "add", "-A")
    scriptkit.git(crlf, "commit", "-q", "-m", "crlf")
    (crlf / "a.py").write_bytes(API_GONE.replace("\n", "\r\n").encode())
    scriptkit.git(crlf, "add", "-A")
    assert run(crlf, "commit")[0] == 3
    (crlf / "a.py").write_bytes(API.replace("\n", "\r\n").replace("MAX_BODY", "LIMIT").encode())
    scriptkit.git(crlf, "add", "-A")
    assert run(crlf, "commit") == (0, "")


@pytest.mark.parametrize(
    "path", ["tests/test_api.py", "docs/guide.py", "README.md", "src/api_test.go", "vendor/x/api.py"]
)
def test_tests_docs_and_vendored_code_are_not_judged(tmp_path: Path, path: str) -> None:
    root = scriptkit.init_repo(tmp_path / "s", {path: API})
    stage(root, {path: API_GONE})
    assert run(root, "commit") == (0, "")


def test_a_person_waiver_at_commit_clears_one_line_and_is_not_honoured_for_the_other_rule(repo: Path) -> None:
    waived = MAKE_GONE + "LDFLAGS += -z execstack  # pragma: allowlist mitigation-removal\n"
    stage(repo, {"Makefile": waived})
    assert run(repo, "commit") == (0, "")
    wrong = MAKE_GONE + "LDFLAGS += -z execstack  # pragma: allowlist guard-removal\n"
    stage(repo, {"Makefile": wrong})
    assert run(repo, "commit")[0] == 1


def test_ci_judges_the_tip_commit_when_no_base_is_named(repo: Path) -> None:
    assert run(repo, "ci") == (0, "")  # the root commit removes nothing
    stage(repo, {"src/api.py": API_GONE})
    scriptkit.git(repo, "commit", "-q", "-m", "drop check")
    code, err = run(repo, "ci")
    assert code == 3 and "src/api.py" in err


def test_ci_judges_the_range_from_the_named_base(repo: Path) -> None:
    scriptkit.git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    stage(repo, {"Makefile": MAKE_GONE})
    scriptkit.git(repo, "commit", "-q", "-m", "one")
    stage(repo, {"src/keep.py": "x = 3\n"})
    scriptkit.git(repo, "commit", "-q", "-m", "two")
    code, err = run(repo, "ci", env={"GITHUB_BASE_REF": "main", "PATH": scriptkit.os_path()})
    assert code == 1 and "Makefile" in err


@pytest.mark.parametrize("name", ["gone", "--output=x", "a b"])
def test_ci_refuses_a_base_it_cannot_resolve(repo: Path, name: str) -> None:
    code, err = run(repo, "ci", env={"GITHUB_BASE_REF": name, "PATH": scriptkit.os_path()})
    assert code == 2 and "does not resolve" in err


def test_a_write_is_judged_against_the_file_on_disk(repo: Path) -> None:
    code, err = run(repo, "tool_use", {"src/api.py": API_GONE})
    assert code == 3 and "src/api.py" in err
    assert run(repo, "tool_use", {"src/api.py": API}) == (0, "")
    scriptkit.write(repo, {"src/api.py": API_GONE})  # disk already holds the removal: HEAD is the baseline
    assert run(repo, "tool_use", {"src/api.py": API_GONE})[0] == 3


def test_a_new_file_binary_text_and_an_out_of_scope_write_are_silent(repo: Path) -> None:
    writes = {"src/new.py": API_GONE, "blob.bin": "\0\0if len(x) > 1: raise E", "tests/test_x.py": API_GONE}
    assert run(repo, "tool_use", writes) == (0, "")


def test_an_agent_cannot_waive_with_a_pragma_it_just_wrote(repo: Path) -> None:
    swap = MAKE_GONE + "LDFLAGS += -z execstack  # pragma: allowlist mitigation-removal\n"
    assert run(repo, "tool_use", {"Makefile": swap})[0] == 1


def test_an_added_copy_of_a_committed_pragma_line_waives_nothing(tmp_path: Path) -> None:
    waived = "r = get(u, verify=False)  # pragma: allowlist mitigation-removal"
    root = scriptkit.init_repo(tmp_path / "c", {"a.py": f"r = get(u, verify=True)\nx = 1\n{waived}\n"})
    assert run(root, "tool_use", {"a.py": f"{waived}\nx = 1\n{waived}\n"})[0] == 1


def test_a_pragma_on_a_committed_line_the_agent_removes_is_honoured(tmp_path: Path) -> None:
    pragma = "  # pragma: allowlist mitigation-removal"
    root = scriptkit.init_repo(tmp_path / "w", {"Makefile": MAKE.rstrip("\n") + pragma + "\n"})
    assert run(root, "tool_use", {"Makefile": MAKE_GONE}) == (0, "")
    scriptkit.git(root, "mv", "Makefile", "Makefile.bak")  # the path HEAD has under this name is gone
    assert run(root, "tool_use", {"Makefile": MAKE_GONE.replace("-O2", "-O3")})[0] == 0


def test_a_pragma_only_on_disk_is_not_a_committed_line(tmp_path: Path) -> None:
    root = scriptkit.init_repo(tmp_path / "d", {"Makefile": MAKE})
    scriptkit.write(root, {"Makefile": MAKE.rstrip("\n") + "  # pragma: allowlist mitigation-removal\n"})
    assert run(root, "tool_use", {"Makefile": MAKE_GONE})[0] == 1


def test_an_agents_commit_reads_the_staged_diff_and_gets_the_agent_waiver_rules(repo: Path) -> None:
    swap = MAKE_GONE + "LDFLAGS += -z execstack  # pragma: allowlist mitigation-removal\n"
    stage(repo, {"Makefile": swap})
    assert run(repo, "agent-commit")[0] == 1
    assert run(repo, "commit") == (0, "")


def test_cmake_lists_and_c_defines_are_judged(tmp_path: Path) -> None:
    root = scriptkit.init_repo(
        tmp_path / "k",
        {"CMakeLists.txt": "add_compile_options(-fstack-protector-strong)\n", "h.h": "#define _FORTIFY_SOURCE 2\n"},
    )
    stage(root, {"CMakeLists.txt": "add_compile_options(-O2)\n", "h.h": "#define X 1\n"})
    code, err = run(root, "commit")
    assert code == 1 and "CMakeLists.txt" in err and "h.h" in err


def test_unreadable_input_is_refused_not_allowed(repo: Path, tmp_path: Path) -> None:
    proc = scriptkit.run_script_full("guard-deletion", NAME, repo, "not json")
    assert proc.returncode == 2 and "refusing to guess" in proc.stderr
    stage(repo, {"src/api.py": API_GONE})
    assert run(repo, "commit", env={"PATH": ""})[0] == 2
    plain = tmp_path / "plain"
    plain.mkdir()
    code, err = run(plain, "commit")
    assert code == 2 and "git diff failed" in err
    proc = scriptkit.run_script_full("guard-deletion", NAME, repo, json.dumps({"event": "tool_use", "writes": ["x"]}))
    assert proc.returncode == 2


def test_a_broken_table_refuses(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mod, "HERE", repo)  # no data/ folder there
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"event": "commit", "repo_root": str(repo)})))
    assert mod.main() == 2
    assert "TableError" in capsys.readouterr().err


def test_an_oversize_change_asks_instead_of_guessing(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mod, "MAX_CHANGED_LINES", 1)
    stage(repo, {"src/api.py": API_GONE})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"event": "commit", "repo_root": str(repo)})))
    assert mod.main() == 3
    assert "too large" in capsys.readouterr().err


def test_a_long_report_is_cut_with_a_count(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mod, "SHOWN", 1)
    stage(repo, {"src/api.py": API_GONE, "Makefile": MAKE_GONE, "src/mw.js": ""})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"event": "commit", "repo_root": str(repo)})))
    assert mod.main() == 1
    assert "and 2 more" in capsys.readouterr().err


def engine(repo: Path, event: str, writes: dict[str, str] | None = None) -> tuple[int, str]:
    return gatekit.judge("guard-deletion", repo, event, writes)


def test_the_engine_runs_the_gate_at_commit_and_at_tool_use(repo: Path) -> None:
    stage(repo, {"Makefile": MAKE_GONE})
    assert engine(repo, gatekit.COMMIT)[0] == 1
    scriptkit.write(repo, {"Makefile": MAKE})
    scriptkit.git(repo, "reset", "-q")
    stage(repo, {"src/keep.py": "x = 9\n"})
    assert engine(repo, gatekit.COMMIT)[0] == 0
    assert engine(repo, gatekit.PRE_TOOL_USE, {"Makefile": MAKE_GONE})[0] == 1
    assert engine(repo, gatekit.PRE_TOOL_USE, {"src/api.py": API_GONE})[0] == 3
    assert engine(repo, gatekit.PRE_TOOL_USE, {"src/api.py": API})[0] == 0


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
