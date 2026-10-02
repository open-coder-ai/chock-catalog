"""block-hook-bypass-in-files: the content pattern line by line, flagged and silent, beside the replayed eval suite."""

from __future__ import annotations

import re

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
    "git config core.hooksPath": OK,
    "git config core.hooksPath > /dev/null": OK,
    "git config --unset core.hooksPath 2>/dev/null || true": OK,
    "git config --get core.hooksPath || echo none": OK,
    "git -c core.hooksPath=/dev/null commit -m x": FLAG,
    "export HUSKY=0": FLAG,
    "HUSKY=1 npm test": OK,
    "  HUSKY: 0": FLAG,
    '"HUSKY": "0",': FLAG,
    '[ "${HUSKY-}" = "0" ] && exit 0': OK,
    'if [ "$HUSKY" = "0" ]; then exit 0; fi': OK,
    "SKIP=flake8 git commit -m x": FLAG,
    "SKIP=": OK,
    "SKIP= git commit -m x": OK,
    "SKIP_TESTS=1 make": OK,
    "MY_SKIP=1 make": OK,
    f'git commit {NV} -m "release"': FLAG,
    'git commit -m "x" --no-veri': FLAG,
    f'git commit -m "fix #12" {NV}': FLAG,
    f'echo "never pass {NV} to git commit"': OK,
    f"# git push {NV} skips hooks": OK,
    "pre-commit uninstall": FLAG,
    "npx lefthook uninstall": FLAG,
    "lefthook install": OK,
    "LEFTHOOK=0 git push": FLAG,
    "LEFTHOOK=1 git push": OK,
    "LEFTHOOK_EXCLUDE=lint git push": FLAG,
    "PRE_COMMIT_ALLOW_NO_CONFIG=1 pre-commit run": FLAG,
    "GIT_CONFIG_KEY_0=core.hooksPath": FLAG,
    'git config core.hooksPath "$HOOKS"': FLAG,
    "git config get core.hooksPath": OK,
    "SKIP ?= lint": FLAG,
    "SKIP = lint": FLAG,
    "pre-commit-skip=1": OK,
    '\tgit commit -am "release v1" ' + NV: FLAG,
    "skip: true": OK,
    "npx husky": OK,
    "git push --no-verbose": OK,
}


@pytest.mark.parametrize(("line", "want"), list(LINES.items()), ids=[line[:60] for line in LINES])
def test_the_pattern_flags_only_a_bypass(line: str, want: bool) -> None:
    assert (PATTERN.search(line) is not None) == want, line


def test_the_pattern_does_not_match_its_own_manifest() -> None:
    """Self-match trap: the bracketed first letters keep the manifest's own lines silent."""
    assert [line for line in MANIFEST.read_text(encoding="utf-8").splitlines() if PATTERN.search(line)] == []
