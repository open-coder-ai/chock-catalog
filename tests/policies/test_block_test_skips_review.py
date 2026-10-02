"""block-test-skips v2: the cases the adversarial review of 0.1.0 raised, each pinned in the direction it was fixed."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from policies import gatekit, scriptkit

mod = scriptkit.load("block-test-skips", "block-test-skips-gate.py")
POLICY = "block-test-skips"


def lines(path: str, text: str) -> list[int]:
    return [f["line"] for f in mod.findings({"event": "tool_use", "writes": {path: text}})]


def engine(tmp_path: Path, path: str, head: str, after: str) -> int:
    """The verdict at the turn's end for `after` over a HEAD holding `head`."""
    repo = scriptkit.init_repo(tmp_path / "r", {path: head})
    scriptkit.write(repo, {path: after})
    return gatekit.judge(POLICY, repo, gatekit.STOP, {path: after})[0]


def test_a_large_test_file_with_many_old_skips_is_judged_within_budget(tmp_path: Path) -> None:
    body = "".join(
        f"def test_{n}():\n" + ("    pytest.skip('x')\n" if n % 25 == 0 else "    assert 1\n") for n in range(3500)
    )
    head = "import pytest\n\n" + body
    started = time.monotonic()
    assert engine(tmp_path, "tests/test_big.py", head, head + "def test_new():\n    assert 1\n") == 0
    assert time.monotonic() - started < 25


def test_a_large_js_file_scopes_in_one_pass() -> None:
    text = "describe('d', () => {\n" + ("  it." + "skip('x', () => {});\n") * 20000 + "});\n"
    started = time.monotonic()
    assert len(lines("src/a.test.js", text)) == 20000
    assert time.monotonic() - started < 10


@pytest.mark.parametrize(
    ("lang", "head", "after"),
    [
        (
            "Tests/CartTests.cs",
            'class CartTests {\n  [Fact(Skip = "x")]\n  public async Task Old() {}\n  public async Task Broken() {}\n}\n',
            'class CartTests {\n  public async Task Old() {}\n  [Fact(Skip = "x")]\n  public async Task Broken() {}\n}\n',
        ),
        (
            "app/CartTest.kt",
            "class CartTest {\n  @" + "Disabled\n  fun `old flaky`() {}\n  fun `broken`() {}\n}\n",
            "class CartTest {\n  fun `old flaky`() {}\n  @" + "Disabled\n  fun `broken`() {}\n}\n",
        ),
    ],
)
def test_a_skip_moved_to_another_test_is_new(tmp_path: Path, lang: str, head: str, after: str) -> None:
    assert engine(tmp_path, lang, head, after) == 1


@pytest.mark.parametrize(
    ("head", "after"),
    [
        (
            "import pytest\n\n\n@pytest.mark.skipif(\n    sys.platform == 'win32',\n    reason='x',\n)\ndef test_a():\n"
            "    assert 1\n",
            "import pytest\n\n\n@pytest.mark.skipif(\n    True,\n    reason='x',\n)\ndef test_a():\n    assert 1\n",
        ),
        (
            "import pytest\n\n\ndef test_a():\n    if os.environ.get('NO_NET'):\n        pytest.skip('x')\n",
            "import pytest\n\n\ndef test_a():\n    if True:\n        pytest.skip('x')\n",
        ),
    ],
)
def test_widening_an_old_python_skip_is_new(tmp_path: Path, head: str, after: str) -> None:
    assert engine(tmp_path, "tests/test_a.py", head, after) == 1


def test_an_old_guarded_skip_under_an_unrelated_edit_is_old(tmp_path: Path) -> None:
    head = "import pytest\n\n\ndef test_a():\n    if not net():\n        pytest.skip('x')\n    assert 1\n"
    assert engine(tmp_path, "tests/test_a.py", head, head.replace("assert 1", "assert 2")) == 0


@pytest.mark.parametrize(
    "text",
    [
        "from pytest import *\n\nskip('x')\n",
        "import pytest\n\nm = pytest.mark\nlater = m.skip\n",
        "def pytest_configure(config):\n    config.option.keyword = 'not test_x'\n",
        "def pytest_configure(config):\n    config.option.deselect.append('tests/test_a.py::x')\n",
    ],
)
def test_python_names_reached_by_star_import_assignment_or_option_are_refused(text: str) -> None:
    assert lines("tests/conftest.py", text)


def test_a_non_utf8_coding_cookie_is_refused() -> None:
    assert lines("tests/test_a.py", "# coding: utf-7\nx = 1\n") == [1]
    assert lines("tests/test_a.py", "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\nx = 1\n") == []


def test_a_go_short_mode_guard_counts_only_when_it_skips_or_returns() -> None:
    returns = "func TestA(t *testing.T) {\n\tif testing.Short() {\n\t\treturn\n\t}\n}\n"
    scales = "func TestA(t *testing.T) {\n\tn := 100\n\tif testing.Short() {\n\t\tn = 10\n\t}\n}\n"
    commented = "func TestA(t *testing.T) {\n\t// if testing.Short() { return }\n}\n"
    assert lines("pkg/a_test.go", returns) == [2]
    assert lines("pkg/a_test.go", scales) == []
    assert lines("pkg/a_test.go", commented) == []


@pytest.mark.parametrize(
    ("path", "text", "found"),
    [
        ("tox.ini", "[testenv:lint]\ncommands = flake8 --ignore=E501 src\n", []),
        ("tox.ini", "[testenv]\ncommands =\n    pytest --deselect tests/test_a.py::x\n", [3]),
        ("pyproject.toml", '[tool.hatch.envs.lint.scripts]\ncheck = "pylint --ignore=migrations src"\n', []),
        ("pyproject.toml", '[tool.hatch.envs.test.scripts]\nrun = "pytest --ignore=tests/slow"\n', [2]),
        ("pytest.ini", "[pytest]\naddopts = -k smoke  # do not run everything\n", []),
        ("pytest.ini", '[pytest]\naddopts = -vk "not test_x"\n', [2]),
        ("pytest.toml", '[pytest]\naddopts = ["--deselect=tests/test_a.py::test_x"]\n', [2]),
        ("setup.cfg", "[tool:pytest]\naddopts = -k 'a #b' ; not this\n", []),
        ("jest.config.unit.js", "module.exports = { testPathIgnorePatterns: ['/cart/'] };\n", [1]),
    ],
)
def test_pytest_options_count_in_pytest_sections_and_pytest_commands(path: str, text: str, found: list[int]) -> None:
    assert lines(path, text) == found


def test_an_unclosed_each_table_stops_the_table_scan() -> None:
    text = "it.each([1]).skip('a', () => {});\n" + "it.each(\n" * 3 + "x\n"
    assert lines("src/a.test.ts", text) == [1]


def test_an_annotation_on_a_declaration_line_names_that_declaration() -> None:
    java = "class AppTest {\n  @Test void a() { assumeTrue(false); }\n  @" + "Disabled\n  void b() {}\n}\n"
    keys = [f["key"] for f in mod.findings({"event": "tool_use", "writes": {"src/test/java/AppTest.java": java}})]
    assert keys[0].startswith("test-skip|AppTest.a|")
    assert keys[1].startswith("test-skip|AppTest.b|")


def test_a_guarded_skip_is_keyed_behind_its_guard() -> None:
    text = "def test_a():\n    while flaky():\n        if not net():\n            pytest.skip('x')\n"
    (found,) = mod.findings({"event": "tool_use", "writes": {"tests/test_a.py": text}})
    assert found["key"] == "test-skip|test_a|while flaky(): => if not net(): => pytest.skip('x')"
