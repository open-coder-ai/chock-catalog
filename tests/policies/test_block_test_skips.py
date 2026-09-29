"""block-test-skips: the script gate that refuses an added skip or focus marker in a test file."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest
from policies import scriptkit

NAME = "block-test-skips-gate.py"
mod = scriptkit.load("block-test-skips", NAME)

# Built by concatenation so this file, itself a test path, never carries a marker the gate refuses.
PYSKIP = "@pytest.mark." + "skip"
PYSKIPIF = "@pytest.mark." + "skipif(sys.platform == 'win32')"
UNITSKIP = "@unittest." + "skip('x')"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHOCK_AGENT_COMMIT", raising=False)


def payload(repo: Path, writes: dict[str, str], event: str = "commit") -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"tests/test_old.py": f"{PYSKIP}\ndef test_old():\n    pass\n"})


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("tests/test_a.py", PYSKIP),
        ("tests/test_a.py", PYSKIPIF),
        ("tests/test_a.py", UNITSKIP),
        ("src/a.test.ts", "it." + "skip('x', () => {});"),
        ("src/a.spec.js", "describe." + "skip('x', () => {});"),
        ("src/a.test.mjs", "test." + "skip('x', () => {});"),
        ("src/a.test.tsx", "xit('x', () => {});"),
        ("src/a.test.cjs", "xdescribe('x', () => {});"),
        ("src/a.spec.ts", "it." + "only('x', () => {});"),
        ("web/__tests__/a.js", "describe." + "only('x', () => {});"),
        ("src/test/java/AppTest.java", "  @" + "Disabled"),
        ("src/test/java/AppTest.java", "  @" + "Ignore"),
        ("pkg/app_test.go", "\tt." + 'Skip("x")'),
        ("pkg/app_test.go", "\tt." + "SkipNow()"),
        ("pkg/app_test.go", "\tt." + 'Skipf("x %d", 1)'),
        ("tests/unit/deep/check.py", PYSKIP),
        ("tests\\win\\test_w.py", PYSKIP),
    ],
)
def test_an_added_skip_in_a_test_file_is_refused(repo: Path, path: str, line: str) -> None:
    found = mod.findings(payload(repo, {path: f"first\n{line}\nlast\n"}))
    assert len(found) == 1
    assert found[0].startswith(path.replace("\\", "/") + ":2: ")


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("tests/test_a.py", "def test_a():"),
        ("tests/test_a.py", "# " + PYSKIP),
        ("src/a.test.ts", "// it." + "skip('x')"),
        ("src/a.test.ts", " * " + "it." + "skip('x')"),
        ("src/a.test.ts", "/* " + "xit('x')"),
        ("src/a.test.ts", "const exit = 1;"),
        ("src/a.test.ts", "expect(items.it).toBe(1);"),
        ("docs/testing.md", PYSKIP),
        ("src/app.py", PYSKIP),
        ("src/testing_utils.py", PYSKIP),
        ("latest/notes.txt", PYSKIP),
        ("src/Skipper.java", "  @" + "Disabled"),
    ],
)
def test_other_lines_and_other_files_are_left_alone(repo: Path, path: str, line: str) -> None:
    assert mod.findings(payload(repo, {path: f"{line}\n"})) == []


def test_a_skip_already_at_head_does_not_block_an_unrelated_edit(repo: Path) -> None:
    edited = f"{PYSKIP}\ndef test_old():\n    pass\n\n\ndef test_new():\n    assert 1\n"
    assert mod.findings(payload(repo, {"tests/test_old.py": edited})) == []


def test_only_the_copies_beyond_head_are_added(repo: Path) -> None:
    doubled = f"{PYSKIP}\ndef test_old():\n    pass\n{PYSKIP}\ndef test_twin():\n    pass\n"
    found = mod.findings(payload(repo, {"tests/test_old.py": doubled}))
    assert [f.split(": ")[0] for f in found] == ["tests/test_old.py:4"]


def test_a_new_file_and_a_repository_without_history_are_all_added(tmp_path: Path) -> None:
    empty = scriptkit.init_repo(tmp_path / "empty")
    found = mod.findings(payload(empty, {"tests/test_x.py": f"{PYSKIP}\n"}))
    assert found == [f"tests/test_x.py:1: {PYSKIP}"]


def test_a_waiver_is_honoured_at_commit_only(repo: Path) -> None:
    waived = f"{PYSKIP}  # chock: allow test-skip -- needs a GPU\n"
    assert mod.findings(payload(repo, {"tests/test_g.py": waived})) == []
    assert len(mod.findings(payload(repo, {"tests/test_g.py": waived}, event="tool_use"))) == 1


def test_a_waived_skip_already_in_head_passes_in_the_agent(tmp_path: Path) -> None:
    waived = f"{PYSKIP}  # chock: allow test-skip -- needs a GPU\n"
    held = scriptkit.init_repo(tmp_path / "h", {"tests/test_g.py": waived})
    assert mod.findings(payload(held, {"tests/test_g.py": waived + "x = 1\n"}, event="tool_use")) == []


def test_a_waiver_is_not_honoured_for_an_agents_commit(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    waived = f"{PYSKIP}  # chock: allow test-skip\n"
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", "1")
    assert len(mod.findings(payload(repo, {"tests/test_g.py": waived}))) == 1
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", "0")
    assert mod.findings(payload(repo, {"tests/test_g.py": waived})) == []


def test_a_long_line_is_truncated_in_the_report(repo: Path) -> None:
    found = mod.findings(payload(repo, {"tests/test_l.py": f"{PYSKIP}  # " + "x" * 300 + "\n"}))
    assert len(found[0]) < 160


def test_main_allows_refuses_and_rejects_bad_input(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def run(text: str) -> tuple[int, str]:
        monkeypatch.setattr("sys.stdin", io.StringIO(text))
        code = mod.main()
        return code, capsys.readouterr().err

    assert run(json.dumps(payload(repo, {"tests/test_ok.py": "def test_ok():\n    assert 1\n"}))) == (0, "")
    code, err = run(json.dumps(payload(repo, {"tests/test_bad.py": f"{PYSKIP}\n"})))
    assert code == 1
    assert "tests/test_bad.py:1" in err
    assert "chock: allow test-skip" in err
    assert run("not json")[0] == 2
    assert run(json.dumps({"event": "commit", "repo_root": str(repo)})) == (0, "")


def test_the_script_runs_as_a_process(repo: Path) -> None:
    code, err = scriptkit.run_script(
        "block-test-skips", NAME, repo, json.dumps(payload(repo, {"tests/test_p.py": f"{PYSKIP}\n"}))
    )
    assert code == 1
    assert "tests/test_p.py:1" in err


def test_the_gate_scopes_to_the_same_test_paths_as_protect_test_integrity() -> None:
    regex = scriptkit.manifest("protect-test-integrity")["hook"]["gate"]["params"]["test_path_regex"]
    assert mod.TEST_PATH.pattern == regex


def test_the_manifest_binds_the_script_at_commit_and_tool_use() -> None:
    gate = scriptkit.manifest("block-test-skips")["hook"]["gate"]
    assert gate["kind"] == "script"
    assert gate["on"] == ["commit", "tool_use"]
    assert gate["params"] == {"script": NAME}
    assert re.search(r"already committed in HEAD", " ".join(gate["message"].split()))
