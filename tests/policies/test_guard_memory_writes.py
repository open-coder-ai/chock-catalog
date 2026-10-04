"""guard-memory-writes: the script gate over agent-memory files."""

from __future__ import annotations

import fnmatch
import io
import json
from pathlib import Path

import pytest
from policies import gatekit, memorykit, scriptkit

NAME = "guard-memory-writes-gate.py"
mod = memorykit.load()

# Built by concatenation so this file never carries a credential-shaped literal.
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
SHA = "0123456789abcdef" * 2 + "01234567"


def fence(n: int, mark: str = "```") -> str:
    return mark + "\n" + "".join(f"body {i}\n" for i in range(n)) + mark + "\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"MEMORY.md": "- old fact\n- old fact\n" + fence(30)})


def rows(repo: Path, writes: dict[str, str], event: str = "commit") -> list[dict]:
    return mod.findings({"event": event, "repo_root": str(repo), "writes": writes})


def check(repo: Path, writes: dict[str, str], event: str = "commit") -> list[str]:
    """Every finding of the written text as `path:line: message`; the engine, not the gate, drops old ones."""
    return [f"{f['path']}:{f['line']}: {f['message']}" for f in rows(repo, writes, event)]


def engine(repo: Path, writes: dict[str, str], event: str = "stop") -> int:
    """The engine's verdict: `stop` lands the writes on disk first, `pre-commit` stages them."""
    if event in (gatekit.STOP, gatekit.COMMIT):
        scriptkit.write(repo, writes)
    if event == gatekit.COMMIT:
        scriptkit.git(repo, "add", "-A")
    return gatekit.judge("guard-memory-writes", repo, event, writes)[0]


@pytest.mark.parametrize(
    "path",
    [
        "MEMORY.md",
        "packages/api/MEMORY.md",
        "CLAUDE.local.md",
        ".claude/memory/notes.md",
        ".claude/memory/deep/x.txt",
        "memory/a.md",
        "memory/topic/a.md",
        ".claude\\memory\\notes.md",
    ],
)
def test_memory_paths_are_judged(repo: Path, path: str) -> None:
    found = check(repo, {path: "diff --git a/x b/x\n"})
    assert len(found) == 1
    assert found[0].startswith(path.replace("\\", "/") + ":1: ")


@pytest.mark.parametrize(
    "path",
    ["README.md", "notes/MEMORY.txt", "src/memory/README.md", "memory/a.txt", "docs/CLAUDE.local.md", "xMEMORY.md"],
)
def test_other_paths_are_never_judged(repo: Path, path: str) -> None:
    assert check(repo, {path: f"diff --git a/x b/x\n{AWS}\n"}) == []


@pytest.mark.parametrize(
    "line",
    [
        "diff --git a/app.py b/app.py",
        "@@ -10,7 +10,8 @@ def run():",
        "@@ -1 +1 @@",
        f"commit {SHA}",
        "index abc1234..def5678 100644",
    ],
)
def test_pasted_git_history_is_refused(repo: Path, line: str) -> None:
    assert check(repo, {"MEMORY.md": f"a fact\n{line}\n"}) == ["MEMORY.md:2: pasted git history"]


@pytest.mark.parametrize(
    "line",
    [
        "the diff --git header is how git names a file pair",
        "commit abc123 fixed it",
        "  index 4 is the retry counter",
        "@@ not a hunk @@",
    ],
)
def test_prose_about_git_is_not_history(repo: Path, line: str) -> None:
    assert check(repo, {"MEMORY.md": f"{line}\n"}) == []


@pytest.mark.parametrize(
    "line",
    [
        "aws: " + AWS,
        "token ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
        "-----BEGIN RSA PRIVATE KEY-----",  # pragma: allowlist secret
        "api_key = 'abcdefghijklmnopqrstuvwx'",  # pragma: allowlist secret
        "password: hunter2hunter2hunter2",  # pragma: allowlist secret
    ],
)
def test_secrets_are_refused(repo: Path, line: str) -> None:
    assert check(repo, {"CLAUDE.local.md": f"note\n{line}\n"}) == ["CLAUDE.local.md:2: secret"]


def test_the_secret_pattern_is_scan_secrets_verbatim() -> None:
    pattern = scriptkit.manifest("scan-secrets")["hook"]["gate"]["params"]["content_pattern"]
    assert mod.SECRET.pattern == pattern


def test_a_fenced_block_over_twenty_lines_is_refused_at_its_opening_line(repo: Path) -> None:
    text = "- how to build:\n" + fence(21)
    assert check(repo, {"memory/build.md": text}) == ["memory/build.md:2: fenced code block of 21 lines (limit 20)"]


@pytest.mark.parametrize("mark", ["```", "~~~", "````"])
def test_a_block_of_exactly_twenty_lines_is_allowed(repo: Path, mark: str) -> None:
    assert check(repo, {"memory/build.md": fence(20, mark)}) == []


def test_fence_kinds_do_not_close_each_other(repo: Path) -> None:
    text = "~~~\n" + "```\n" + "".join(f"body {i}\n" for i in range(25)) + "~~~\n"
    assert check(repo, {"memory/a.md": text}) == ["memory/a.md:1: fenced code block of 26 lines (limit 20)"]


def test_an_unclosed_fence_runs_to_the_end_of_the_file(repo: Path) -> None:
    text = "```\n" + "".join(f"body {i}\n" for i in range(21))
    assert check(repo, {"memory/a.md": text}) == ["memory/a.md:1: fenced code block of 21 lines (limit 20)"]


def long_block_key(text: str) -> str:
    (row,) = [r for r in mod.judge("MEMORY.md", text) if r["key"].startswith("long-block|")]
    return row["key"]


def test_a_long_block_key_carries_the_opener_and_a_body_hash() -> None:
    key = long_block_key("- how to build:\n```sh\n" + "".join(f"body {i}\n" for i in range(21)) + "```\n")
    assert key.startswith("long-block|```sh|") and len(key.split("|")[2]) == 16


def test_a_long_block_key_follows_the_body_not_the_position() -> None:
    assert long_block_key(fence(21)) == long_block_key("- a fact\n\n" + fence(21))
    assert long_block_key(fence(21)) != long_block_key(fence(22))


def test_an_untouched_long_block_stays_old(repo: Path) -> None:
    assert engine(repo, {"MEMORY.md": "- old fact\n- old fact\n" + fence(30) + "- new fact\n"}) == 0


def test_a_line_added_inside_an_old_long_block_is_refused(repo: Path) -> None:
    assert engine(repo, {"MEMORY.md": "- old fact\n- old fact\n" + fence(31)}) != 0


def test_an_old_long_block_shrunk_under_the_limit_is_allowed(repo: Path) -> None:
    assert engine(repo, {"MEMORY.md": "- old fact\n- old fact\n" + fence(20)}) == 0


def test_duplicates_are_reported_at_the_later_line(repo: Path) -> None:
    text = "- prefers  tabs\n- uses uv\n* prefers tabs\n1. uses uv\n"
    assert check(repo, {"memory/a.md": text}) == [
        "memory/a.md:3: duplicates line 1",
        "memory/a.md:4: duplicates line 2",
    ]


def test_headings_blank_lines_rules_and_code_are_not_duplicates(repo: Path) -> None:
    text = "# Facts\n\n- one\n\n# Facts\n\n---\n---\n" + "```\nsame\nsame\n}\n}\n```\n```\nsame\n```\n"
    assert check(repo, {"memory/a.md": text}) == []


def test_a_secret_is_never_printed_in_the_document(repo: Path) -> None:
    stdin = json.dumps({"event": "commit", "repo_root": str(repo), "writes": {"memory/a.md": f"- key {AWS}\n"}})
    proc = scriptkit.run_script_full("guard-memory-writes", NAME, repo, stdin)
    assert AWS not in proc.stdout + proc.stderr
    (row,) = json.loads(proc.stdout)["findings"]
    assert row["key"].startswith("secret|")


def test_the_baseline_run_judges_as_the_change_run_does(repo: Path) -> None:
    stdin = {"event": "commit", "repo_root": str(repo), "writes": {"memory/a.md": "diff --git a b\n"}}
    change = scriptkit.run_script_full("guard-memory-writes", NAME, repo, json.dumps(stdin))
    baseline = scriptkit.run_script_full("guard-memory-writes", NAME, repo, json.dumps({**stdin, "baseline": True}))
    assert change.stdout == baseline.stdout


def test_each_secret_line_is_reported(repo: Path) -> None:
    text = f"- key {AWS}\n- key {AWS}\n"
    assert check(repo, {"memory/a.md": text}) == ["memory/a.md:1: secret", "memory/a.md:2: secret"]


def test_a_repeated_history_line_is_history_not_a_duplicate(repo: Path) -> None:
    text = "diff --git a/x b/x\ndiff --git a/x b/x\n"
    assert check(repo, {"memory/a.md": text}) == [
        "memory/a.md:1: pasted git history",
        "memory/a.md:2: pasted git history",
    ]


def test_a_new_repeat_line_reports_the_duplicate_when_it_is_the_only_finding(repo: Path) -> None:
    assert check(repo, {"memory/a.md": "same fact\nsame fact\n"}) == ["memory/a.md:2: duplicates line 1"]


def test_clean_memory_is_allowed_on_every_event(repo: Path) -> None:
    text = "# Prefs\n\n- terse answers\n- uv, not pip\n"
    assert check(repo, {"MEMORY.md": text}, event="tool_use") == []
    assert check(repo, {}) == []


def test_findings_are_sorted_by_path(repo: Path) -> None:
    found = check(repo, {"memory/b.md": "diff --git a b\n", "MEMORY.md": "diff --git a b\n"})
    assert [f.split(":")[0] for f in found] == ["MEMORY.md", "memory/b.md"]


def test_main_allows_refuses_and_rejects_bad_input(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def run(text: str) -> tuple[int, str]:
        monkeypatch.setattr("sys.stdin", io.StringIO(text))
        code = mod.main()
        return code, capsys.readouterr().err

    def body(writes: dict[str, str]) -> str:
        return json.dumps({"event": "commit", "repo_root": str(repo), "writes": writes})

    assert run(body({"MEMORY.md": "- fact\n"})) == (0, "")
    code, err = run(body({"MEMORY.md": "diff --git a b\n"}))
    assert code == 1
    assert "MEMORY.md:1: pasted git history" in err
    assert "No waiver exists" in err
    assert run("{")[0] == 2
    assert run(json.dumps({"event": "commit", "repo_root": str(repo)})) == (0, "")


def test_the_script_runs_as_a_process(repo: Path) -> None:
    stdin = json.dumps({"event": "tool_use", "repo_root": str(repo), "writes": {"MEMORY.md": f"{AWS}\n"}})
    code, err = scriptkit.run_script("guard-memory-writes", NAME, repo, stdin)
    assert code == 1
    assert "MEMORY.md:1: secret" in err


def test_the_manifest_binds_the_script_at_commit_and_tool_use() -> None:
    gate = scriptkit.manifest("guard-memory-writes")["hook"]["gate"]
    assert gate["kind"] == "script"
    assert gate["on"] == ["commit", "tool_use"]
    assert gate["params"] == {"script": NAME}


HOME = "/Users/dev"
OUTSIDE = [
    f"{HOME}/.claude/projects/-work-app/memory/MEMORY.md",
    f"{HOME}/.claude/projects/-work-app/memory/prefs.md",
    "/root/.claude/projects/p/memory/deep/topic.txt",
    "C:/Users/dev/.claude/projects/p/memory/a.md",
    f"{HOME}/.claude/CLAUDE.md",
    "/memories/notes.md",
    "/memories/repo/facts.md",
]
NOT_MEMORY = [
    f"{HOME}/.claude/settings.json",
    f"{HOME}/.claude/projects/p/session.jsonl",
    f"{HOME}/.claude/projects/p/memory",
    f"{HOME}/project/CLAUDE.md",
    f"{HOME}/.claude/CLAUDE.md.bak",
    f"{HOME}/memories/a.md",
]


@pytest.mark.parametrize("path", OUTSIDE)
def test_outside_memory_stores_are_judged(repo: Path, path: str) -> None:
    assert check(repo, {path: "diff --git a/x b/x\n"}, event="tool_use") == [f"{path}:1: pasted git history"]


@pytest.mark.parametrize("path", NOT_MEMORY)
def test_other_outside_paths_are_never_judged(repo: Path, path: str) -> None:
    assert check(repo, {path: f"diff --git a/x b/x\n{AWS}\n"}, event="tool_use") == []


def test_the_manifest_globs_admit_the_outside_paths_the_script_judges() -> None:
    declared = scriptkit.manifest("guard-memory-writes")["hook"]["gate"]["outside_repo"]
    globs = [g.replace("~", HOME, 1) for g in declared]
    admitted = [p for p in OUTSIDE if p.startswith((HOME, "/memories"))]
    assert all(any(fnmatch.fnmatchcase(p, g) for g in globs) for p in admitted)
    assert not any(fnmatch.fnmatchcase(p, g) for p in NOT_MEMORY for g in globs)


def test_the_manifest_declares_the_outside_stores() -> None:
    gate = scriptkit.manifest("guard-memory-writes")["hook"]["gate"]
    assert gate["outside_repo"] == ["~/.claude/projects/*/memory/**", "~/.claude/CLAUDE.md", "/memories/**"]
