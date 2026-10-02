"""block-test-skips v2: the fourth review round's cases (JSX in tables, table owners), pinned both ways."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import gatekit, scriptkit

mod = scriptkit.load("block-test-skips", "block-test-skips-gate.py")


def lines(path: str, text: str) -> list[int]:
    return [f["line"] for f in mod.findings({"event": "tool_use", "writes": {path: text}})]


def engine(tmp_path: Path, head: str, after: str) -> int:
    repo = scriptkit.init_repo(tmp_path / "r", {"tests/test_a.py": head})
    scriptkit.write(repo, {"tests/test_a.py": after})
    return gatekit.judge("block-test-skips", repo, gatekit.STOP, {"tests/test_a.py": after})[0]


@pytest.mark.parametrize(
    ("text", "found"),
    [
        (
            "it.each([\n  ['button', <Button>Save</Button>],\n  ['link', <Link>Go</Link>],\n])('renders %s', (_, el) => {\n"
            "  render(el);\n});\n\nit.each([[1]]).skip('later %i', () => {});\n",
            [8],
        ),
        ("n = x++ / 2; m = y-- / 3;\ntest.each([[1]]).skip('x', () => {});\n", [2]),
        ("const half = a * /x/.exec(s).length;\ntest.each([[1]]).skip('x', () => {});\n", [2]),
        ("it.each((\ntest.each([[1]]).skip('x', () => {});\n", [2]),
        ("it.each`a`.skip('x', () => {});\nit.each`b\n", [1]),
        ("it.each([1]).only('x', () => {});\nit.each)\n", [1]),
    ],
)
def test_tables_after_jsx_division_or_an_unclosed_table_are_still_matched(text: str, found: list[int]) -> None:
    assert lines("src/Button.test.tsx", text) == found


def test_an_unclosed_go_short_block_is_passed_over() -> None:
    text = "func TestA(t *testing.T) {\n\tif testing.Short() {\n"
    assert lines("pkg/a_test.go", text) == []


@pytest.mark.parametrize(
    ("head", "after"),
    [
        (
            "def test_a():\n    run([pytest.param(1, marks=pytest.mark.skip)], fast=True)\n    run([1], fast=False)\n",
            "def test_a():\n    run([1], fast=True)\n    check([pytest.param(1, marks=pytest.mark.skip)], fast=False)\n",
        ),
        (
            "def test_a():\n    check(fast_cases, [pytest.param(1, marks=pytest.mark.skip)])\n    check(slow_cases, [])\n",
            "def test_a():\n    check(fast_cases, [])\n    check(slow_cases, [pytest.param(1, marks=pytest.mark.skip)])\n",
        ),
        (
            "@pytest.mark.parametrize(['x'], [pytest.param(1, marks=pytest.mark.skip)])\n"
            "@pytest.mark.parametrize(['y'], [1])\ndef test_a(x, y):\n    pass\n",
            "@pytest.mark.parametrize(['x'], [1])\n"
            "@pytest.mark.parametrize(['y'], [pytest.param(1, marks=pytest.mark.skip)])\ndef test_a(x, y):\n    pass\n",
        ),
    ],
)
def test_a_row_moved_between_owners_of_the_same_test_is_new(tmp_path: Path, head: str, after: str) -> None:
    assert engine(tmp_path, "import pytest\n\n\n" + head, "import pytest\n\n\n" + after) == 1


def test_a_bare_table_statement_is_owned_by_its_kind() -> None:
    (found,) = mod.findings(
        {"event": "tool_use", "writes": {"tests/test_a.py": "[pytest.param(1, marks=pytest.mark.skip)]\n"}}
    )
    assert found["key"] == "test-skip||Expr :: pytest.param(1, marks=pytest.mark.skip)"


def test_a_nested_jest_list_is_judged_whole() -> None:
    keys = [
        f["key"]
        for f in mod.findings(
            {
                "event": "tool_use",
                "writes": {"jest.config.js": "module.exports = { testPathIgnorePatterns: [['/a/'], '/b/'] };\n"},
            }
        )
    ]
    assert keys == [
        "test-config||testPathIgnorePatterns|/b/",
        "test-config||testPathIgnorePatterns|[['/a/'], '/b/']",
    ]
