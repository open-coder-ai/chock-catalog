"""protect-ci-workflows: the hardening review's shell-guard cases (REVIEW-infra.md section 5, K and Q tables)."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

POLICY = "protect-ci-workflows"
GUARD = guardkit.load_guard(POLICY)
WORKFLOW = ".github/workflows/ci.yml"
PATCH_TEXT = f"--- a/{WORKFLOW}\n+++ b/{WORKFLOW}\n@@ -1 +1 @@\n-on: push\n+on: workflow_dispatch\n"
SOURCE_PATCH = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"


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


def test_a_refusal_printed_by_the_guard_names_the_path(capsys: pytest.CaptureFixture[str]) -> None:
    assert GUARD.run(["rm", ".github/workflows/ci.yml"]) == 1
    assert ".github/workflows/ci.yml" in capsys.readouterr().err
