"""Gates bound at tool_use in wave 2, run through chock's runner at the agent events, false positives included."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import gatekit, scriptkit

UNSAFE = "block-unsafe-code-execution"
DEPS = "verify-dependency-exists"
INTEGRITY = "protect-test-integrity"
# Built by concatenation so this file never carries a primitive or a pragma the gates refuse.
CALL = "ev" + "al(data)"
PRAGMA = "  # pragma: allowlist " + "exec"
TWO_TESTS = "def test_a():\n    assert f(1) == 1\n\n\ndef test_b():\n    assert f(2) == 2\n"


def repo_with(tmp_path: Path, files: dict[str, str]) -> Path:
    return scriptkit.init_repo(tmp_path / "r", files)


@pytest.mark.parametrize("policy", [UNSAFE, DEPS, INTEGRITY])
def test_the_gate_is_bound_at_commit_and_tool_use(policy: str) -> None:
    assert gatekit.gate_spec(policy)["on"] == ["commit", "tool_use"]


def test_a_dynamic_execution_write_is_refused_and_a_method_call_is_not(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"app.py": "x = 1\n"})
    assert (
        gatekit.judge(UNSAFE, repo, gatekit.PRE_TOOL_USE, {"app.py": f"x = {CALL}\n"}, {"app.py": f"x = {CALL}\n"})[0]
        == 1
    )
    assert gatekit.judge(UNSAFE, repo, gatekit.STOP, {"app.py": f"x = {CALL}\n"})[0] == 1
    assert gatekit.judge(UNSAFE, repo, gatekit.PRE_TOOL_USE, {"app.py": "m = pattern.exec(text)\n"}) == (0, "")


def test_a_new_pragma_written_by_the_agent_is_not_honoured(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"app.py": "x = 1\n"})
    line = f"x = {CALL}{PRAGMA}\n"
    assert gatekit.judge(UNSAFE, repo, gatekit.PRE_TOOL_USE, {"app.py": line}, {"app.py": line})[0] == 1
    assert gatekit.judge(UNSAFE, repo, gatekit.STOP, {"app.py": line})[0] == 1


def test_a_pragma_line_already_in_head_is_honoured_and_never_re_flagged(tmp_path: Path) -> None:
    line = f"x = {CALL}{PRAGMA}\n"
    repo = repo_with(tmp_path, {"app.py": line})
    assert gatekit.judge(UNSAFE, repo, gatekit.PRE_TOOL_USE, {"app.py": line + "y = 2\n"}, {"app.py": line}) == (0, "")
    assert gatekit.judge(UNSAFE, repo, gatekit.STOP, {"app.py": line + "y = 2\n"}) == (0, "")


def test_a_primitive_committed_long_ago_does_not_block_an_unrelated_edit_at_the_turns_end(tmp_path: Path) -> None:
    old = f"x = {CALL}\n"
    repo = repo_with(tmp_path, {"app.py": old})
    (repo / "app.py").write_text(old + "y = 2\n", encoding="utf-8")
    assert gatekit.judge(UNSAFE, repo, gatekit.STOP, {"app.py": old + "y = 2\n"}) == (0, "")


def test_an_added_dependency_off_the_allowlist_is_refused_at_tool_use(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"requirements.txt": "requests\n", ".chock/dependency-allowlist.txt": "requests\n"})
    code, err = gatekit.judge(DEPS, repo, gatekit.PRE_TOOL_USE, {"requirements.txt": "requests\nnot-a-real-pkg\n"})
    assert code == 1
    assert "not-a-real-pkg" in err
    assert "ask a person" in err
    assert gatekit.judge(DEPS, repo, gatekit.STOP, {"requirements.txt": "requests\nnot-a-real-pkg\n"})[0] == 1


def test_a_listed_or_already_present_dependency_passes_at_tool_use(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"requirements.txt": "unlisted-old\n", ".chock/dependency-allowlist.txt": "requests\n"})
    assert gatekit.judge(DEPS, repo, gatekit.PRE_TOOL_USE, {"requirements.txt": "unlisted-old\nrequests\n"}) == (0, "")
    assert gatekit.judge(DEPS, repo, gatekit.PRE_TOOL_USE, {"requirements.txt": "unlisted-old\n# note\n"}) == (0, "")
    assert gatekit.judge(DEPS, repo, gatekit.PRE_TOOL_USE, {"README.md": "any-name\n"}) == (0, "")


def test_a_write_that_weakens_a_test_is_refused_and_a_rewrite_that_keeps_its_assertions_is_not(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"tests/test_a.py": TWO_TESTS})
    weaker = "def test_a():\n    assert f(1) == 1\n"
    assert gatekit.judge(INTEGRITY, repo, gatekit.PRE_TOOL_USE, {"tests/test_a.py": weaker})[0] == 1
    changed = TWO_TESTS.replace("f(2) == 2", "f(2) == 3")
    assert gatekit.judge(INTEGRITY, repo, gatekit.PRE_TOOL_USE, {"tests/test_a.py": changed}) == (0, "")
    grown = TWO_TESTS + "\n\ndef test_c():\n    assert f(3) == 3\n"
    assert gatekit.judge(INTEGRITY, repo, gatekit.PRE_TOOL_USE, {"tests/test_a.py": grown}) == (0, "")


def test_a_vacuous_assertion_is_refused_and_the_waiver_is_not_honoured_in_the_agent(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"tests/test_a.py": TWO_TESTS})
    vacuous = TWO_TESTS.replace("assert f(2) == 2", "assert True")
    assert gatekit.judge(INTEGRITY, repo, gatekit.PRE_TOOL_USE, {"tests/test_a.py": vacuous})[0] == 1
    waived = vacuous + "\n# chock: allow test-integrity\n"
    assert gatekit.judge(INTEGRITY, repo, gatekit.PRE_TOOL_USE, {"tests/test_a.py": waived})[0] == 1
    assert gatekit.judge(INTEGRITY, repo, gatekit.STOP, {"tests/test_a.py": waived})[0] == 1


def test_a_new_test_file_and_a_non_test_file_pass_and_a_stop_after_a_clean_turn_passes(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"tests/test_a.py": TWO_TESTS, "src/app.py": "x = 1\n"})
    assert gatekit.judge(INTEGRITY, repo, gatekit.PRE_TOOL_USE, {"tests/test_new.py": TWO_TESTS}) == (0, "")
    assert gatekit.judge(INTEGRITY, repo, gatekit.PRE_TOOL_USE, {"src/app.py": "x = 2\n"}) == (0, "")
    assert gatekit.judge(INTEGRITY, repo, gatekit.STOP, {"tests/test_a.py": TWO_TESTS}) == (0, "")
