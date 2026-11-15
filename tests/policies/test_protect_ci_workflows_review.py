"""protect-ci-workflows: the hardening review's cases (REVIEW-infra.md section 5), rebuilt from their descriptions."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit

POLICY = "protect-ci-workflows"
GUARD = guardkit.load_guard(POLICY)
WORKFLOW = ".github/workflows/ci.yml"
PATCH_TEXT = f"--- a/{WORKFLOW}\n+++ b/{WORKFLOW}\n@@ -1 +1 @@\n-on: push\n+on: workflow_dispatch\n"
SOURCE_PATCH = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"

# id -> (path, caught): the Edit/Write cases. Five drive CI indirectly and are out of scope (declared).
EDITS = {
    "E01": (WORKFLOW, True),
    "E01v": (".github/workflows/reusable.yml", True),
    "E02": (WORKFLOW, True),
    "E02v": (".github/actions/setup/action.yml", True),
    "E03": (WORKFLOW, True),
    "E03v": (WORKFLOW, True),
    "E04": (WORKFLOW, True),
    "E04v": (WORKFLOW, True),
    "E05": (WORKFLOW, True),
    "E05v": ("pyproject.toml", False),
    "E06": (".gitlab-ci.yml", True),
    "E06v": (".circleci/config.yml", True),
    "E07": (".github/CODEOWNERS", True),
    "E07v": ("docs/CODEOWNERS", True),
    "E08": (".pre-commit-config.yaml", True),
    "E08v": (".husky/pre-commit", True),
    "E09": ("Makefile", False),
    "E09v": ("package.json", False),
    "E10": ("codecov.yml", False),
    "E10v": (".github/zizmor.yml", False),
    "E11": (WORKFLOW, True),
}
# Correct work the gate asks about by design (disclosed): fixture, non-GitHub action.yml, README, vendored copy, template.
CORRECT_WRITES = {
    "Z01": ("docs/ci.md", False),
    "Z02": ("src/workflows/engine.py", False),
    "Z03": (".github/ISSUE_TEMPLATE/bug.md", False),
    "Z04": ("tests/fixtures/repo/.github/workflows/sample.yml", True),
    "Z05": ("bot/action.yml", True),
    "Z06": (".github/workflows/README.md", True),
    "Z07": ("docs/Jenkinsfile-notes.txt", False),
    "Z08": ("src/actions/index.ts", False),
    "Z09": ("third_party/lib/.github/workflows/ci.yml", True),
    "Z10": (".github/FUNDING.yml", False),
    "Z11": ("docs/renovate.md", False),
    "Z12": (".gitlab/merge_request_templates/default.md", True),
    "Z13": ("tests/test_ci_workflow.py", False),
}
CAUGHT_EDITS = [case for case, (_, caught) in EDITS.items() if caught]
UNCAUGHT_EDITS = [case for case, (_, caught) in EDITS.items() if not caught]

# id -> (command, blocked). `{patch}` is a patch file that edits the workflow; `{other}` one that edits source.
WEAKENING = {
    "K01": ("sed -i 's/under=80/under=50/' .github/workflows/ci.yml", True),
    "K01v": ("perl -pi -e 's/under=80/under=50/' .github/workflows/ci.yml", True),
    "K02": ("rm .github/workflows/ci.yml", True),
    "K02v": ("git rm -q .github/workflows/ci.yml", True),
    "K03": ("cat > .github/workflows/ci.yml <<'EOF'\non: workflow_dispatch\nEOF", True),
    "K03v": ("echo '        continue-on-error: true' | tee -a .github/workflows/ci.yml", True),
    "K04": ("""yq -i '.jobs.test.steps[0]."continue-on-error" = true' .github/workflows/ci.yml""", True),
    "K04v": (
        "python3 -c \"import pathlib; p=pathlib.Path('.github/workflows/ci.yml'); p.write_text(p.read_text().replace('a','b'))\"",
        True,
    ),
    "K05": ("mv /tmp/ci.yml .github/workflows/ci.yml", True),
    "K05v": ("curl -fsSL https://example.com/ci.yml -o .github/workflows/ci.yml", True),
    "K06": ("git checkout HEAD~5 -- .github/workflows/ci.yml", True),
    "K06v": ("git apply {patch}", True),
    "K07": ("python3 tools/fix_ci.py", False),  # declared: a script's own writes are not in the command text
    "K07v": ("patch -p1 < {patch}", True),
    "K08": ("gh workflow disable ci.yml", False),  # declared: a server-side route
    "K08v": ("gh api -X PUT repos/o/r/contents/.github/workflows/ci.yml -f message=x -f content=b24=", False),
    "K09": (
        "sed -i 's/allow_failure: false/allow_failure: true/' .gitlab-ci.yml",
        False,
    ),  # declared: GitHub paths only
    "K09v": ("rm Jenkinsfile", False),
    "K10": ("cd .github/workflows && rm ci.yml", True),
    "K10v": ('f=.github/workflows/ci.yml; rm "$f"', True),
    "K11": ("find .github/workflows -name '*.yml' -delete", True),
    "K11v": (": > .github/workflows/ci.yml", True),
    "K12": ("sed 's/80/50/' .github/workflows/ci.yml | sponge .github/workflows/ci.yml", True),
    "K12v": (
        "awk '{gsub(/80/,\"50\")}1' .github/workflows/ci.yml > /tmp/x && cp /tmp/x .github/workflows/ci.yml",
        True,
    ),
}
READS = {
    "Q01": "cat .github/workflows/ci.yml",
    "Q02": "grep -rn 'uses:' .github/workflows",
    "Q03": "actionlint .github/workflows/ci.yml && zizmor .github/workflows",
    "Q04": "git diff -- .github/workflows && git log --oneline -- .github/workflows/ci.yml",
    "Q05": "cp .github/workflows/ci.yml /tmp/ci.bak",
    "Q06": "git add .github/workflows/ci.yml && git commit -m 'ci: pin actions'",
    "Q07": "echo 'see .github/workflows/ci.yml' >> NOTES.md",
    "Q08": "git checkout -b fix/.github/workflows-typo",
    "Q09": "gh workflow run ci.yml && gh run watch",
    "Q10": "sed -n '1,20p' .github/workflows/ci.yml",
    "Q11": """python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))\"""",
    "Q12": "tar czf /tmp/wf.tgz .github/workflows",
    "Q13": "rm -rf node_modules/some-pkg/.github",
    "Q14": "chock sync --repo .",
    "Q15": "find .github/workflows -name '*.yml' | xargs yamllint",
    "Q16": "rm -rf build/workflows",
    "Q17": "diff .github/workflows/ci.yml templates/ci.yml > /tmp/ci.diff",
    "Q18": "wc -l .github/workflows/ci.yml 2>&1 | head -1",
    "Q19": "mkdir -p .github/actions/setup",
    "Q20": "git stash push -m wip -- src/",
}


def fill(command: str, patches: dict[str, str]) -> str:
    """The command with `{patch}` and `{other}` replaced by real patch files (braces in awk and shell stay)."""
    return command.replace("{patch}", patches["patch"]).replace("{other}", patches["other"])


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {WORKFLOW: "on: push\n", "src/app.py": "x = 1\n"})


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate judges this commit as an agent's, as the test process's own environment says."""
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.delenv("CHOCK_AGENT_COMMIT", raising=False)


@pytest.fixture
def person(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CLAUDECODE", "AI_AGENT", "CHOCK_AGENT_COMMIT"):
        monkeypatch.delenv(name, raising=False)


def committed(repo: Path, path: str) -> tuple[int, str]:
    """Stage a change to `path` and judge the commit through the runner."""
    scriptkit.write(repo, {path: "changed\n"})
    scriptkit.git(repo, "add", "-A")
    return gatekit.judge(POLICY, repo, gatekit.COMMIT)


@pytest.mark.usefixtures("agent")
@pytest.mark.parametrize("case", CAUGHT_EDITS)
def test_an_agents_commit_of_a_protected_path_asks(repo: Path, case: str) -> None:
    code, err = committed(repo, EDITS[case][0])
    assert code == 1, case
    assert EDITS[case][0] in err


@pytest.mark.usefixtures("agent")
@pytest.mark.parametrize("case", UNCAUGHT_EDITS)
def test_an_agents_commit_of_a_file_that_drives_ci_indirectly_is_not_judged(repo: Path, case: str) -> None:
    assert committed(repo, EDITS[case][0]) == (0, "")


@pytest.mark.usefixtures("person")
@pytest.mark.parametrize("case", [*CAUGHT_EDITS, *UNCAUGHT_EDITS])
def test_a_persons_commit_is_not_judged(repo: Path, case: str) -> None:
    assert committed(repo, EDITS[case][0]) == (0, "")


@pytest.mark.parametrize("case", CAUGHT_EDITS)
def test_the_write_before_it_lands_still_asks(repo: Path, case: str) -> None:
    path = EDITS[case][0]
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "new\n"}, {path: "new\n"})
    assert code == 3, case
    assert path in err


@pytest.mark.parametrize("case", CAUGHT_EDITS)
def test_the_turns_end_still_warns(repo: Path, case: str) -> None:
    path = EDITS[case][0]
    scriptkit.write(repo, {path: "changed\n"})
    code, err = gatekit.judge(POLICY, repo, gatekit.STOP, {path: "changed\n"})
    assert code == 4, case
    assert path in err


@pytest.mark.usefixtures("agent")
@pytest.mark.parametrize("case", sorted(CORRECT_WRITES))
def test_correct_writes_are_asked_as_before_at_the_write_and_at_an_agents_commit(repo: Path, case: str) -> None:
    path, asked = CORRECT_WRITES[case]
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "x\n"}, {path: "x\n"})[0] == (3 if asked else 0)
    assert committed(repo, path)[0] == (1 if asked else 0)


GATE = scriptkit.load(POLICY, "protect-ci-workflows-gate.py")


@pytest.mark.parametrize("stdin", ["", "not json", "[]", '{"writes": 3}', '{"event": "tool_use", "writes": null}'])
def test_a_gate_input_it_cannot_read_is_a_fault_not_an_allow(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stdin: str
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert GATE.main() == 2
    assert "not the gate JSON" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("event", "code"), [("tool_use", 3), ("agent-commit", 3), ("commit", 0), ("ci", 0), ("push", 0)]
)
def test_the_gate_asks_only_at_the_events_an_agent_acts_at(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], event: str, code: int
) -> None:
    payload = json.dumps({"event": event, "writes": {WORKFLOW: "x\n", "src/app.py": "x\n"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert GATE.main() == code
    err = capsys.readouterr().err
    assert (WORKFLOW in err) == (code == 3)
    assert "src/app.py" not in err


def test_the_gate_runs_as_a_process_and_asks_with_its_words_on_stderr(repo: Path) -> None:
    payload = json.dumps({"event": "agent-commit", "writes": {WORKFLOW: "x\n"}})
    code, err = scriptkit.run_script(POLICY, "protect-ci-workflows-gate.py", repo, payload)
    assert code == 3
    assert err.startswith(f"{WORKFLOW}: CI, hook or bot configuration")
    assert scriptkit.run_script(POLICY, "protect-ci-workflows-gate.py", repo, "not json")[0] == 2


def test_a_control_character_in_a_file_name_does_not_reach_the_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = json.dumps({"event": "tool_use", "writes": {".github/workflows/a\x1b[31m.yml": "x\n"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert GATE.main() == 3
    assert "\x1b" not in capsys.readouterr().err


@pytest.mark.usefixtures("agent")
def test_an_agents_commit_of_an_ordinary_file_passes(repo: Path) -> None:
    assert committed(repo, "src/app.py") == (0, "")


@pytest.fixture
def patches(tmp_path: Path) -> dict[str, str]:
    workflow, other = tmp_path / "weaken-ci.patch", tmp_path / "fix-app.patch"
    workflow.write_text(PATCH_TEXT, encoding="utf-8")
    other.write_text(SOURCE_PATCH, encoding="utf-8")
    return {"patch": str(workflow), "other": str(other)}


@pytest.mark.parametrize("case", [case for case, (_, blocked) in WEAKENING.items() if blocked])
def test_a_weakening_command_is_refused(case: str, patches: dict[str, str]) -> None:
    assert GUARD.check(fill(WEAKENING[case][0], patches)) is not None, case


@pytest.mark.parametrize("case", [case for case, (_, blocked) in WEAKENING.items() if blocked])
def test_the_refusal_names_the_path_that_matched(case: str, patches: dict[str, str]) -> None:
    reason = GUARD.check(fill(WEAKENING[case][0], patches))
    assert reason is not None
    assert ".github/workflows" in reason, case


@pytest.mark.parametrize("case", [case for case, (_, blocked) in WEAKENING.items() if not blocked])
def test_a_declared_miss_still_runs(case: str) -> None:
    assert GUARD.check(WEAKENING[case][0]) is None, case


@pytest.mark.parametrize("case", sorted(READS))
def test_a_read_or_unrelated_command_passes(case: str) -> None:
    assert GUARD.check(READS[case]) is None, case


def test_the_message_names_the_path_that_matched() -> None:
    reason = GUARD.check("echo x > docs/a.txt && sed -i s/a/b/ .github/workflows/release.yml")
    assert reason is not None
    assert ".github/workflows/release.yml" in reason
    assert "docs/a.txt" not in reason


def test_a_path_in_the_message_cannot_carry_a_control_character() -> None:
    reason = GUARD.check("rm '.github/workflows/a\x1b[31mb.yml'")
    assert reason is not None
    assert "\x1b" not in reason


@pytest.mark.parametrize(
    "command",
    [
        "git checkout -b fix/.github/workflows/typo",
        "git checkout -B fix/.github/workflows/typo origin/main",
        "git checkout --orphan .github/workflows/x",
        "git -C . checkout -b .github/workflows/x",
    ],
)
def test_a_new_branch_name_is_not_a_path(command: str) -> None:
    assert GUARD.check(command) is None


@pytest.mark.parametrize(
    "command",
    [
        "git checkout -b fix HEAD~1 -- .github/workflows/ci.yml",
        "git checkout HEAD~1 -- .github/workflows/ci.yml",
        "git checkout .github/workflows/ci.yml",
    ],
)
def test_a_checkout_of_a_workflow_is_still_refused_beside_a_branch(command: str) -> None:
    assert GUARD.check(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "python3 -c \"print(open('.github/workflows/ci.yml').read())\"",
        "python3 -c \"import yaml; print(yaml.safe_load(open('.github/workflows/ci.yml'))['on'])\"",
        "node -e \"console.log(require('fs').readFileSync('.github/workflows/ci.yml', 'utf8'))\"",
        "ruby -e 'puts File.read(\".github/workflows/ci.yml\")'",
    ],
)
def test_an_interpreter_that_only_reads_a_workflow_passes(command: str) -> None:
    assert GUARD.check(command) is None


@pytest.mark.parametrize(
    "command",
    [
        "python3 -c \"open('.github/workflows/ci.yml', 'w').write('x')\"",
        "python3 -c \"open('.github/workflows/ci.yml', mode='a').write('x')\"",
        "python3 -c \"import os; os.remove('.github/workflows/ci.yml')\"",
        "python3 -c \"import shutil; shutil.copy('/tmp/x', '.github/workflows/ci.yml')\"",
        "node -e \"require('fs').writeFileSync('.github/workflows/ci.yml', 'x')\"",
        "node -e \"require('fs').unlinkSync('.github/workflows/ci.yml')\"",
        'ruby -e \'File.write(".github/workflows/ci.yml", "x")\'',
        "perl -e 'open(F, \">.github/workflows/ci.yml\"); print F 1'",
        "perl -pi -e 's/a/b/' .github/workflows/ci.yml",
        "python3 -c \"import subprocess; subprocess.run(['sed', '-i', 's/a/b/', '.github/workflows/ci.yml'])\"",
    ],
)
def test_an_interpreter_that_can_write_a_workflow_is_still_refused(command: str) -> None:
    assert GUARD.check(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf node_modules/.github",
        "rm -rf ./node_modules/a/b/.github",
        "rm -rf packages/x/node_modules/y/.github",
    ],
)
def test_a_dependencys_own_dot_github_folder_may_be_removed(command: str) -> None:
    assert GUARD.check(command) is None


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf .github",
        "rm -rf node_modules/x/.github/workflows",
        "rm node_modules/x/.github/workflows/ci.yml",
        "rm -rf src/.github",
    ],
)
def test_the_repositorys_own_dot_github_and_a_workflow_anywhere_are_still_refused(command: str) -> None:
    assert GUARD.check(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "yq -i '.a = 1' .github/workflows/ci.yml",
        "yq --inplace '.a = 1' .github/workflows/ci.yml",
        "yq e -i '.a = 1' .github/workflows/ci.yml",
        "yq -ie '.a = 1' .github/dependabot.yml",
        "curl -o .github/workflows/ci.yml https://example.com/ci.yml",
        "curl -fsSLo .github/workflows/ci.yml https://example.com/ci.yml",
        "curl --output .github/workflows/ci.yml https://example.com/ci.yml",
        "curl --output=.github/workflows/ci.yml https://example.com/ci.yml",
        "curl -o.github/workflows/ci.yml https://example.com/ci.yml",
        "wget -O .github/workflows/ci.yml https://example.com/ci.yml",
        "wget --output-document=.github/workflows/ci.yml https://example.com/ci.yml",
        "wget -qO .github/workflows/ci.yml https://example.com/ci.yml",
        "sponge .github/workflows/ci.yml",
        "sponge -a .github/actions/setup/action.yml",
        "git apply --directory=.github/workflows fix.patch",
        "git -C . apply {patch}",
        "git apply --apply {patch}",
        "patch .github/workflows/ci.yml fix.diff",
        "patch -i {patch}",
        "patch --input={patch} -p1",
    ],
)
def test_the_other_in_place_writers_are_refused(command: str, patches: dict[str, str]) -> None:
    assert GUARD.check(fill(command, patches)) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        "yq '.on' .github/workflows/ci.yml",
        "yq -i '.a = 1' config/app.yml",
        "curl -o /tmp/ci.yml https://example.com/ci.yml",
        "curl https://example.com/ci.yml",
        "curl -sS https://example.com/.github/workflows/ci.yml",
        "curl --silent --output /tmp/ci.yml https://example.com/ci.yml",
        "wget -O /tmp/x https://example.com/ci.yml",
        "sponge /tmp/out",
        "git apply {other}",
        "git apply --check {patch}",
        "git apply --stat {patch}",
        "git apply --numstat {patch}",
        "git apply --summary {patch}",
        "patch -p1 < {other}",
        "patch -i {other}",
        "patch -p1 < /nonexistent/never.patch",
        "git apply /nonexistent/never.patch",
        "patch src/app.py fix.diff",
    ],
)
def test_reads_and_unrelated_writers_of_those_commands_pass(command: str, patches: dict[str, str]) -> None:
    assert GUARD.check(fill(command, patches)) is None, command


def test_a_patch_is_read_from_the_directory_the_command_runs_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patches: dict[str, str]
) -> None:
    Path(patches["patch"]).replace(tmp_path / "rel.patch")
    (tmp_path / "empty").mkdir()
    monkeypatch.chdir(tmp_path)
    assert GUARD.check("git apply rel.patch") is not None
    monkeypatch.chdir(tmp_path / "empty")
    assert GUARD.check("git apply rel.patch") is None


@pytest.mark.parametrize(
    "patch",
    [
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n",
        "rename to .github/workflows/ci.yml\n",
        "copy to .github/actions/x/action.yml\n",
        "--- a/.github/dependabot.yml\t2026-11-01 10:00:00\n",
        "+++ b/.github/workflows/ci.yml\r\n",
    ],
)
def test_every_header_of_a_patch_that_names_a_protected_path_counts(tmp_path: Path, patch: str) -> None:
    file = tmp_path / "x.patch"
    file.write_text("noise\n" + patch, encoding="utf-8")
    assert GUARD.check(f"git apply {file}") is not None


def test_a_patch_too_large_to_read_whole_is_read_up_to_a_cap(tmp_path: Path) -> None:
    file = tmp_path / "big.patch"
    file.write_text("x\n" * 600_000 + PATCH_TEXT, encoding="utf-8")
    assert GUARD.check(f"git apply {file}") is None  # past the cap: not judged, and the manifest says so


def test_a_patch_that_is_a_directory_or_not_text_is_not_judged(tmp_path: Path) -> None:
    binary = tmp_path / "b.patch"
    binary.write_bytes(b"\xff\xfe\x00\n" + PATCH_TEXT.encode("utf-8"))
    assert GUARD.check(f"git apply {tmp_path}") is None
    assert GUARD.check(f"git apply {binary}") is not None  # undecodable bytes are replaced, the header still reads


@pytest.mark.parametrize(
    "command",
    [
        'f=.github/workflows/ci.yml; rm "$f"',
        "f=.github/workflows/ci.yml && rm ${f}",
        'dir=.github; rm -rf "$dir/workflows"',
        'f=.github/workflows/ci.yml; echo x > "$f"',
        'f=.github/workflows/ci.yml\nrm "$f"',
        'a=.github; b=$a/workflows; rm -rf "$b"',
        'f=.github/workflows/ci.yml; g=$f; mv /tmp/x "$g"',
    ],
)
def test_a_path_held_in_a_variable_is_read_from_the_line(command: str) -> None:
    assert GUARD.check(command) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        'f=notes.md; rm "$f"',
        'rm "$f"',
        'f=.github/workflows/ci.yml; cat "$f"',
        'f=.github/workflows/ci.yml; f=notes.md; rm "$f"',
        'rm "${undefined}"',
        "rm '$f'",
    ],
)
def test_a_variable_that_does_not_hold_a_protected_path_passes(command: str) -> None:
    assert GUARD.check(command) is None, command


def test_a_refusal_printed_by_the_guard_names_the_path(capsys: pytest.CaptureFixture[str]) -> None:
    assert GUARD.run(["rm", ".github/workflows/ci.yml"]) == 1
    assert ".github/workflows/ci.yml" in capsys.readouterr().err
