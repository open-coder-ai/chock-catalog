"""block-hook-bypass-in-files: the content pattern line by line, flagged and silent, beside the replayed eval suite."""

from __future__ import annotations

import re
import time

import pytest
import yaml
from trees import ROOT

MANIFEST = ROOT / "base" / "block-hook-bypass-in-files" / "manifest.yaml"
PATTERN = re.compile(yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["hook"]["gate"]["params"]["content_pattern"])
FLAG, OK = True, False
NV = "--no-" + "verify"
LINES = {
    '"prepare": "git config core.hooksPath .githooks"': FLAG,
    "git config --get core.hooksPath": OK,
    "hooks=$(git config core.hooksPath)": OK,
    "hooks=$(git config core.hooksPath 2>/dev/null)": OK,
    "git config --local core.hooksPath 2>/dev/null": OK,
    'echo "core.hooksPath is $(git config core.hooksPath)"': OK,
    "git config core.hooksPath": OK,
    "git config core.hooksPath > /dev/null": OK,
    "git config --unset core.hooksPath 2>/dev/null || true": OK,
    'git config core.hooksPath "$HOOKS"': FLAG,
    "git config --local core.hooksPath .githooks": FLAG,
    "git -c core.hooksPath=/dev/null commit -m x": FLAG,
    'git -c "core.hooksPath=/dev/null" commit -m x': FLAG,
    "export GIT_CONFIG_KEY_0 := core.hooksPath": FLAG,
    "GIT_CONFIG_KEY_0=core.hooksPath": FLAG,
    """GIT_CONFIG_PARAMETERS="'core.hooksPath'=/x" git commit""": FLAG,
    "export HUSKY=0": FLAG,
    "HUSKY=1 npm test": OK,
    "  HUSKY: 0": FLAG,
    '"HUSKY": "0",': FLAG,
    '"HUSKY":"0"': FLAG,
    "HUSKY ?=0": FLAG,
    "HUSKY =0": FLAG,
    ': "${HUSKY:=0}"': FLAG,
    '[ "${HUSKY-}" = "0" ] && exit 0': OK,
    'if [ "$HUSKY" = "0" ]; then exit 0; fi': OK,
    "SKIP=flake8 git commit -m x": FLAG,
    "SKIP=": OK,
    "SKIP= git commit -m x": OK,
    "SKIP_TESTS=1 make": OK,
    "SKIP=0": OK,
    "SKIP=1": OK,
    "SKIP=true": OK,
    "local SKIP=$1": OK,
    "--skip) SKIP=1; shift ;;": OK,
    'SKIP="${SKIP:-}"': OK,
    "SKIP ?= lint": FLAG,
    "SKIP: no-commit-to-branch": FLAG,
    f'git commit {NV} -m "release"': FLAG,
    'git commit -m "x" --no-veri': FLAG,
    f'git commit -m "fix #12" {NV}': FLAG,
    f"\t$(GIT) commit -m release {NV}": FLAG,
    f'"$GIT" push {NV}': FLAG,
    f"${{GIT}} push origin main {NV}": FLAG,
    f"git push --tags && cargo publish {NV}": OK,
    "git merge --no-verify-signatures feature": OK,
    "git pull --no-verify-signatures": OK,
    f'echo "never pass {NV} to git commit"': OK,
    f"# git push {NV}": OK,
    "pre-commit uninstall": FLAG,
    "python -m pre_commit uninstall": FLAG,
    "npx lefthook uninstall": FLAG,
    "lefthook install": OK,
    "LEFTHOOK=0 git push": FLAG,
    "LEFTHOOK=1 git push": OK,
    "LEFTHOOK_EXCLUDE=lint git push": FLAG,
    "PRE_COMMIT_ALLOW_NO_CONFIG=1 pre-commit run": FLAG,
    "git config get core.hooksPath": OK,
    "pre-commit-skip=1": OK,
    '\tgit commit -am "release v1" ' + NV: FLAG,
    "skip: true": OK,
    "npx husky": OK,
    "git push --no-verbose": OK,
    '"SKIP":"eslint"': FLAG,
    "git --config-env=core.hooksPath=VAR commit": FLAG,
    f'git commit -m "docs & tests" {NV}': FLAG,
    f'git commit -m "release; bump deps" {NV}': FLAG,
    f"git commit -m 'a|b' {NV}": FLAG,
    f'"ship": "git commit -m \\"a & b\\" {NV}"': FLAG,
    f'git commit -m "x" && cargo publish {NV}': OK,
    f'echo "a" | git commit -F - {NV}': FLAG,
    "LEFTHOOK_CONFIG=/tmp/x.yml lefthook run": FLAG,
}


@pytest.mark.parametrize(("line", "want"), list(LINES.items()), ids=[line[:60] for line in LINES])
def test_the_pattern_flags_only_a_bypass(line: str, want: bool) -> None:
    assert (PATTERN.search(line) is not None) == want, line


def test_the_pattern_does_not_match_its_own_manifest() -> None:
    """Self-match trap: the bracketed first letters keep the manifest's own lines silent."""
    assert [line for line in MANIFEST.read_text(encoding="utf-8").splitlines() if PATTERN.search(line)] == []


@pytest.mark.parametrize(
    "line",
    [
        "git commit " * 5000 + "HUSKY",
        "git config " * 5000 + "core.hooksPath",
        " config core.hooksPath" * 3000,
        "git push x" * 5000 + " --no-veri" + "x",
        "HUSKY " * 10000 + "=",
    ],
    ids=["git-commit-run", "config-run", "hookspath-run", "push-run", "husky-run"],
)
def test_a_long_line_is_judged_in_linear_time(line: str) -> None:
    """The engine runs re.search on every added line with no length cap; a crafted line must not hang a commit."""
    started = time.perf_counter()
    PATTERN.search(line)
    assert time.perf_counter() - started < 1.0
