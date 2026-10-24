"""protect-ci-workflows 0.2.7: the shell guard matches the folded path, from the directory a prior cd left."""

from __future__ import annotations

import pytest
from policies import guardkit

GUARD = guardkit.load_guard("protect-ci-workflows")

REFUSED = [
    "rm -rf .github//workflows",
    "rm -rf .github/./workflows",
    "rm -rf .github/x/../workflows",
    "rm -rf ./.github/workflows",
    "rm -rf .GITHUB/WORKFLOWS",
    "rm .Github/Workflows/ci.yml",
    "rm -rf .github/workflows::$INDEX_ALLOCATION",
    "rm -rf .github/workflows.",
    "rm -rf '.github/workflows '",
    "rm -rf .github\\\\workflows",
    "rm -rf /repo/.github//workflows",
    "rm -rf .github//dependabot.yml",
    "rm -rf .github/Dependabot.YAML",
    "echo x > .github//workflows/ci.yml",
    "echo x >> .github/./actions/setup/action.yml",
    "cd .github && rm -rf workflows",
    "cd .github; echo x > workflows/ci.yml",
    "cd .github/workflows && rm ci.yml",
    "cd .github/workflows && rm *",
    "pushd .github && rm -r workflows",
    "cd /repo && cd .github && sed -i s/a/b/ workflows/ci.yml",
    "cd sub && rm -rf ../.github/workflows",
    "cd .github && git checkout HEAD~1 -- workflows",
    "cd .github && cp /tmp/x dependabot.yml",
    "(cd .github && rm -rf workflows)",
    "rm -rf .github",
    "rm -rf .github/",
    "mv .github /tmp/old-github",
    "rm -rf ./.github",
    "bash -c 'cd .github && rm -rf workflows'",
]
ALLOWED = [
    "cat .github/workflows/ci.yml",
    "cd .github && cat workflows/ci.yml",
    "cd .github && ls workflows",
    "cd .github && rm notes.md",
    "cd .github && cd .. && rm -rf workflows",
    "cd .github && popd && rm -rf workflows",
    "cd docs && rm -rf workflows/old",
    'cd "$DIR" && rm -rf workflows',
    "cp .github/workflows/ci.yml /tmp/ci.yml",
    "cp .github//workflows/ci.yml /tmp/ci.yml",
    "rm -rf .github-old",
    "rm -rf build/github/workflows",
    "ls .github",
    "gh workflow run ci.yml",
    "cd -",
    "cd",
]


@pytest.mark.parametrize("raw", REFUSED)
def test_an_equivalent_spelling_of_a_protected_path_is_refused(raw: str) -> None:
    assert GUARD.check(raw) is not None, raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_reads_and_other_directories_pass(raw: str) -> None:
    assert GUARD.check(raw) is None, raw
