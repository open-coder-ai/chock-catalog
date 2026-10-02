"""chock_destructive: the one verdict table block-destructive-commands and rtk-dangerous-actions-blocker both read.

Each case names the table row it must hit, and runs against both guards, so a verdict cannot drift between the two
policies; the table itself must be the same bytes and version in each.
"""

from __future__ import annotations

import hashlib
import re

import pytest
from policies import guard_cases_destructive as authored
from policies import guard_cases_destructive_review as review
from policies import guardkit

CASES = authored.CASES + review.CASES
FALLBACK = authored.FALLBACK + review.FALLBACK
POLICIES = ("block-destructive-commands", "rtk-dangerous-actions-blocker")
GUARDS = {policy: guardkit.load_guard(policy) for policy in POLICIES}
TABLE = GUARDS[POLICIES[0]].chock_destructive.TABLE


def digest(policy: str) -> dict[str, str]:
    package = guardkit.impl_dir(policy) / guardkit.DESTRUCTIVE
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(package.glob("*.py"))}


def test_both_policies_ship_the_same_table() -> None:
    assert digest(POLICIES[0]) == digest(POLICIES[1])
    assert len(digest(POLICIES[0])) >= 6
    tables = {policy: guard.chock_destructive for policy, guard in GUARDS.items()}
    assert {t.TABLE_VERSION for t in tables.values()} == {"1.0.0"}
    assert tables[POLICIES[0]].TABLE == tables[POLICIES[1]].TABLE
    for policy, table in tables.items():
        assert f"base/{policy}/implementations/chock_destructive" in table.__file__.replace("\\", "/")


def test_only_the_two_destructive_guards_ship_the_table() -> None:
    shipping = {
        p.parent.parent.name for p in (guardkit.ROOT / "base").glob(f"*/implementations/{guardkit.DESTRUCTIVE}")
    }
    assert shipping == set(POLICIES)


def test_every_row_is_proven_and_every_case_names_a_row() -> None:
    hit = {row for _, row in [*CASES, *FALLBACK] if row}
    assert hit == set(TABLE), sorted(set(TABLE) ^ hit)


def expected(row: str | None) -> tuple[int, str]:
    if row is None:
        return 0, ""
    verdict, text = TABLE[row]
    return verdict, ("BLOCKED: " if verdict == 1 else "CONFIRM: ") + text.split("{0}")[0]


def run(policy: str, command: str, capsys: pytest.CaptureFixture[str], *, fallback: bool = False) -> tuple[int, str]:
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CHOCK_RAW_COMMAND", command)
        patch.delenv("CHOCK_TOOL", raising=False)
        if fallback:
            patch.setenv("CHOCK_ARGV_FALLBACK", "1")
        else:
            patch.delenv("CHOCK_ARGV_FALLBACK", raising=False)
        code = GUARDS[policy].run(command.split())
    return code, capsys.readouterr().err


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize(("command", "row"), CASES, ids=[c[:70] for c, _ in CASES])
def test_the_table_row_decides(policy: str, command: str, row: str | None, capsys: pytest.CaptureFixture[str]) -> None:
    code, err = run(policy, command, capsys)
    want, prefix = expected(row)
    assert (code, err.startswith(prefix)) == (want, True), (policy, command, err)
    assert row is not None or err == ""


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize(("command", "row"), FALLBACK, ids=[c[:70] for c, _ in FALLBACK])
def test_an_unsplittable_command_fails_closed(
    policy: str, command: str, row: str | None, capsys: pytest.CaptureFixture[str]
) -> None:
    code, err = run(policy, command, capsys, fallback=True)
    want, prefix = expected(row)
    assert (code, err.startswith(prefix)) == (want, True), (policy, command, err)


@pytest.mark.parametrize("policy", POLICIES)
def test_the_fallback_flag_alone_adds_the_quote_blind_reading(policy: str, capsys: pytest.CaptureFixture[str]) -> None:
    """Balanced quotes the engine still could not split: the flag makes the guard read the text without its quotes."""
    command = "echo 'a; git push --mirror backup'"
    assert run(policy, command, capsys) == (0, "")
    code, err = run(policy, command, capsys, fallback=True)
    assert code == 1
    assert err.startswith("BLOCKED: git push --mirror")


@pytest.mark.parametrize("policy", POLICIES)
def test_argv_is_rejoined_as_typed_when_no_raw_command_is_set(
    policy: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CHOCK_RAW_COMMAND", raising=False)
    monkeypatch.setenv("CHOCK_ARGV_FALLBACK", "1")
    assert GUARDS[policy].run(["bash", "-c", "'usermod", "-L", "x"]) == 1
    assert capsys.readouterr().err.startswith("BLOCKED: usermod -L")


def test_every_message_is_one_line_and_names_an_alternative() -> None:
    for row, (verdict, text) in TABLE.items():
        assert "\n" not in text, row
        assert verdict in (1, 3), row
        assert re.search(r"Ask the person|person's call|confirm", text), row
