"""block-no-verify 0.4.0: the bypasses and false refusals the adversarial review of the HP04 change found, each pinned."""

from __future__ import annotations

import shlex

import pytest
from policies import guardkit

BLOCK, ASK, OK = 1, 3, 0
GUARD = guardkit.load_guard("block-no-verify")

ROWS: list[tuple[str, int]] = [
    # B1: arguments given to an alias defined on the same line
    ("git -c alias.ci=commit ci -n -m wip", BLOCK),
    ("git -c alias.ci=commit ci --no-verify -m wip", BLOCK),
    ("git -c alias.ci='!git commit' ci -n -m x", BLOCK),
    ("HUSKY=0 git -c alias.c=commit c -m x", BLOCK),
    ("git -c alias.c=c c", ASK),  # an alias of itself is read to the depth limit, then asked
    ("git -c alias.ci=commit ci -m wip", OK),
    ("git -c alias.lg='log --oneline' lg -n 5", OK),
    # B2: value-taking options are each subcommand's own
    ("git am -m -n x.patch", BLOCK),
    ("git am -c --no-verify x.patch", BLOCK),
    ("git rebase -m --no-verify main", BLOCK),
    ("git pull -t --no-verify origin main", BLOCK),
    ("git merge --squash --no-verify feature", BLOCK),
    ("git merge -m --no-verify feature", OK),  # the message is --no-verify; git commits it as text
    ("git commit -tn", OK),  # -t takes its value attached: the template file is n
    ("git commit -t tmpl -n", BLOCK),
    ("git commit -mn", OK),
    # B3: rebase --exec clustered and abbreviated
    ("git rebase -ix 'git commit --amend --no-edit --no-verify' main", BLOCK),
    ("git rebase --exe 'git commit --amend -n' main", BLOCK),
    ("git rebase --ex='HUSKY=0 git commit --amend' main", BLOCK),
    ("git rebase -ix 'make test' main", OK),
    ("git rebase --empty=drop main", OK),
    # B4: GIT_CONFIG_* and config-file redirection, also left set for later commands
    ("GIT_CONFIG_COUNT=+1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x", BLOCK),
    ("GIT_CONFIG_COUNT=' 1' GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/x git commit -m x", BLOCK),
    ("export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null", BLOCK),
    ("export GIT_CONFIG_PARAMETERS=\"'core.hooksPath=/dev/null'\"", BLOCK),
    ("export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.c GIT_CONFIG_VALUE_0='commit -n'", BLOCK),
    ("export GIT_CONFIG_GLOBAL=/tmp/g", ASK),
    ("export GIT_DIR=/tmp/o.git", ASK),
    ("declare -x GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/x; git commit -m x", BLOCK),
    (
        "$env:GIT_CONFIG_COUNT=1; $env:GIT_CONFIG_KEY_0='core.hooksPath'; $env:GIT_CONFIG_VALUE_0='/x'; git commit",
        BLOCK,
    ),
    ("set GIT_CONFIG_COUNT=1&& set GIT_CONFIG_KEY_0=core.hooksPath&& set GIT_CONFIG_VALUE_0=x&& git commit", BLOCK),
    (
        "set -x GIT_CONFIG_COUNT 1; set -x GIT_CONFIG_KEY_0 core.hooksPath; set -x GIT_CONFIG_VALUE_0 x; git commit",
        BLOCK,
    ),
    ("HOME=/tmp/h git commit -m x", ASK),
    ("XDG_CONFIG_HOME=/tmp/x git push", ASK),
    ("export GIT_DIR=.git", OK),
    ("export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=x", OK),
    ("HOME=/tmp/h git log", OK),
    # B5: a block on the line wins over an ask found first
    ("git -c alias.x='commit-tree HEAD^{tree}' -c core.hooksPath=/dev/null commit -m x", BLOCK),
    ("git rebase -x 'git update-ref refs/x HEAD' --no-verify main", BLOCK),
    # B6: ANSI-C and locale quoting
    ("git commit $'-n' -m x", BLOCK),
    ("git commit $'--no-verify' -m x", BLOCK),
    ("git commit $'--no-\\x76erify' -m x", BLOCK),
    ('git commit $"--no-verify" -m x', BLOCK),
    ("git commit $'--no-\\166erify' -m x", BLOCK),  # octal escape
    ('git -c "alias.c=commit -n -m \'x" c', BLOCK),  # an alias value whose quoting does not balance
    ("git commit -m $'it\\'s' -n", BLOCK),
    ("git commit -m $'line one\\nline two'", OK),
    # B7: brace expansion
    ("git commit -m x {--no-verify,}", BLOCK),
    ("git commit -m x {-n,-q}", BLOCK),
    ("git commit -m '{--no-verify,}'", OK),
    # B10: cmd `set` names are case-insensitive
    ("set husky=0&& git commit -m x", BLOCK),
    ("set HUSKY=0", BLOCK),
    # false refusals the review found
    ("grep -rn update-ref src # it's a check", OK),
    ("git log --grep=$'don\\'t' -- src/update-ref.c", OK),
    ("make test SKIP=slow", OK),
    ("make release HUSKY=0", BLOCK),
    ("git --git-dir=$PWD/.git commit -m x", OK),
    # non-blocking findings closed while here
    ("uv run git commit -n -m x", BLOCK),
    ("poetry run git commit --no-verify", BLOCK),
    ("fish -c 'git commit --no-verify'", BLOCK),
    ("busybox sh -c 'git commit -n'", BLOCK),
    ("iex 'git commit --no-verify -m x'", BLOCK),
    ("git -c help.autocorrect=1 comit -n -m x", ASK),
    ("git send-pack origin main", ASK),
    ("git -c core.hooksPath=/dev/null checkout main", BLOCK),
    ("LEFTHOOK_CONFIG=/dev/null git commit -m x", BLOCK),
    ("uv run pytest -n auto", OK),
    # round 2: an open here-document, launcher option values, remove-section, fish --command, .NET setter
    ("export HUSKY=0 <<y", BLOCK),
    ("export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null <<y", BLOCK),
    ("export CHOCK_ALLOW=1 <<y", BLOCK),
    ("cat <<y\nexport HUSKY=0", ASK),  # the open body hides what the line leaves set
    ("cat <<EOF\nhello\nEOF", OK),
    ("uv run --python 3.12 git commit -n -m x", BLOCK),
    ("pnpm --filter app exec git commit -n -m x", BLOCK),
    ("uvx --from pre-commit==3.7 pre-commit uninstall", BLOCK),
    ("uvx --from pre-commit pre-commit run --all-files", OK),
    ("npx --version", OK),
    ("git config --global --remove-section core", ASK),
    ("git config remove-section core", ASK),
    ("git config --remove-section alias", OK),
    ("fish --command='git commit --no-verify -m x'", BLOCK),
    ("fish -ic 'git commit -n -m x'", BLOCK),
    ("fish --command 'git status'", OK),
    ("[Environment]::SetEnvironmentVariable('HUSKY','0'); git commit -m x", BLOCK),
    ("[Environment]::SetEnvironmentVariable('GIT_DIR','C:/o.git'); git commit -m x", ASK),
    ("export XDG_CONFIG_HOME=$HOME/.config", OK),
    # round 3: a here-document body is input, not syntax; a shell behind a launcher is read
    ("git commit -F- <<'EOF'\nmsg with --no-verify and it's\nEOF", OK),
    ("git commit -F- <<-EOF\n\tit's about core.hooksPath\n\tEOF", OK),
    ('echo "<<X"\ngit commit -m it\'s --no-verify', BLOCK),  # a quoted marker opens no body
    ("uv run bash -c 'git commit --no-verify -m x'", BLOCK),
    ("uv run bash -c 'pytest -q'", OK),
    # final pass: a lone double quote in a here-document inside $() sends the lexer to its fallback
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" -n', BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)"', OK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" -nq', BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" -na', BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" "-n"', BLOCK),
    ("git commit -m \"$(cat <<'EOF'\nsay \"hi\nEOF\n)\" '-n'", BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" -n""', BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" -"n"', BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" \\-n', BLOCK),
    ('git -C . commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" -nv', BLOCK),
    ("git commit -m \"$(cat <<'EOF'\nsay \"hi\nEOF\n)\" $'-n'", BLOCK),
    ("git commit -m \"$(cat <<'EOF'\nsay \"hi\nEOF\n)\" $'\\x2dn'", BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" $"-n"', BLOCK),
    ('git commit -m "$(cat <<\'EOF\'\nsay "hi\nEOF\n)" {-n,}', BLOCK),
    ("fish -c 'git status'", OK),
]


@pytest.mark.parametrize(("command", "want"), ROWS, ids=[c[:70] for c in (r[0] for r in ROWS)])
@pytest.mark.parametrize("tool", ["", "bash"])
def test_the_review_case_gets_its_verdict(
    command: str, want: int, tool: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    monkeypatch.delenv("CHOCK_ARGV_FALLBACK", raising=False)
    if tool:
        monkeypatch.setenv("CHOCK_TOOL", tool)
    else:
        monkeypatch.delenv("CHOCK_TOOL", raising=False)
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    code = GUARD.run(argv)
    err = capsys.readouterr().err
    assert code == want, f"{command!r} gave {code}, wanted {want}; stderr={err!r}"


@pytest.mark.parametrize(
    ("command", "tool"),
    [
        ("echo get-started; git commit -m x --no-verif\\y", ""),
        ("git commit -m x --no-ver`ify", ""),
        ("git commit -m x --no-ver`ify", "powershell"),
    ],
)
def test_an_unknown_shell_is_read_both_ways(
    command: str, tool: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without CHOCK_TOOL a word that looks like PowerShell must not hide a bash escape, nor the reverse."""
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    monkeypatch.delenv("CHOCK_ARGV_FALLBACK", raising=False)
    if tool:
        monkeypatch.setenv("CHOCK_TOOL", tool)
    else:
        monkeypatch.delenv("CHOCK_TOOL", raising=False)
    assert GUARD.run(command.split()) == BLOCK
    assert capsys.readouterr().err.startswith("BLOCKED: ")


def test_reading_both_ways_restores_the_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHOCK_TOOL", "unknown")
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "ls")
    assert GUARD.run(["ls"]) == OK
    import os  # noqa: PLC0415

    assert os.environ["CHOCK_TOOL"] == "unknown"
