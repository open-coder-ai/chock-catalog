"""protect-agent-config: eighth review round -- `o` and `O` in a short-option cluster take the next word, a lone `-` ends the
options, escapes decoded to a fixed point, program options and output files of git commands given directly."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from policies import guard_cases_eighth as eighth
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
POLICIES = guardkit.policies_with_shellparse()
DESTRUCTIVE = guardkit.load_guard("block-destructive-commands")
NO_VERIFY = guardkit.load_guard("block-no-verify")


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".claude", ".cursor", ".chock", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    monkeypatch.delenv("CHOCK_TOOL", raising=False)
    return tmp_path


@pytest.fixture(params=POLICIES, ids=POLICIES)
def sp(request: pytest.FixtureRequest):
    module = guardkit.load_shellparse(request.param)
    yield module
    for name in [n for n in sys.modules if n == module.__name__ or n.startswith(f"{module.__name__}.")]:
        del sys.modules[name]


@pytest.mark.parametrize(
    ("raw", "name", "args"),
    [
        ("bash -co pipefail 'rm a'", "rm", ["a"]),
        ("bash -oc pipefail 'rm a'", "rm", ["a"]),
        ("bash -Oc extglob 'rm a'", "rm", ["a"]),
        ("bash -cO extglob 'rm a'", "rm", ["a"]),
        ("bash -c -oe pipefail 'rm a'", "rm", ["a"]),
        ("bash -coO pipefail extglob 'rm a'", "rm", ["a"]),
        ("sh -c - 'rm a'", "rm", ["a"]),
        ("dash -c -- 'rm a'", "rm", ["a"]),
        ("eval - rm a", "-", ["rm", "a"]),
        ("pwsh -Command - rm a", "-", ["rm", "a"]),
    ],
)
def test_an_o_in_a_cluster_takes_the_next_word_and_a_lone_dash_ends_the_options(
    sp, raw: str, name: str, args: list[str]
) -> None:
    found = sp.commands(raw)
    assert (found[0].name, found[0].args) == (name, args)


@pytest.mark.parametrize("raw", eighth.B1_REFUSED)
def test_a_clustered_option_before_the_script_does_not_hide_it(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", eighth.B1_ALLOWED)
def test_its_ordinary_twin_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("raw", eighth.DESTRUCTIVE_REFUSED)
def test_block_destructive_commands_reads_the_same_clusters(raw: str) -> None:
    assert DESTRUCTIVE.check(raw)[0] == 1, raw


@pytest.mark.parametrize("raw", eighth.DESTRUCTIVE_ALLOWED)
def test_and_allows_the_ordinary_ones(raw: str) -> None:
    assert DESTRUCTIVE.check(raw) is None, raw


@pytest.mark.parametrize("raw", eighth.NO_VERIFY_REFUSED)
def test_block_no_verify_reads_the_same_clusters(raw: str) -> None:
    assert NO_VERIFY.check(raw), raw


@pytest.mark.parametrize("raw", eighth.B2_REFUSED)
def test_an_escape_inside_an_escaped_script_is_decoded_until_it_is_stable(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", eighth.B2_ALLOWED)
def test_an_ordinary_double_quoted_script_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("raw", [*eighth.S1_REFUSED, *eighth.S2_REFUSED, *eighth.S3_REFUSED])
def test_a_program_option_url_or_output_file_that_names_a_protected_path_is_refused(raw: str) -> None:
    assert guard.check(raw) in (guard.REASON, guard.BLIND), raw


@pytest.mark.parametrize("raw", [*eighth.S1_ALLOWED, *eighth.S2_ALLOWED, *eighth.S3_ALLOWED])
def test_the_same_options_with_an_ordinary_value_are_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw
