"""block-test-skips v2: the cases the adversarial review of 0.1.0 raised, each pinned in the direction it was fixed."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from policies import gatekit, scriptkit

mod = scriptkit.load("block-test-skips", "block-test-skips-gate.py")
POLICY = "block-test-skips"
LS = chr(0x2028)


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


# Round 2 of the review.


@pytest.mark.parametrize(
    "opener",
    ["// see test.each(\n", "const doc = 'uses it.each(';\n", "/* it.each( */\n", "// note" + LS],
)
def test_a_comment_or_string_cannot_open_an_each_table(opener: str) -> None:
    text = opener + "test.each([[1]]).skip('x %i', () => {});\n"
    assert lines("src/a.test.ts", text) == [2]


@pytest.mark.parametrize(
    ("path", "text", "found"),
    [
        ("tox.ini", "[testenv]\nsetenv =\n    PYTEST_ADDOPTS = --deselect tests/test_a.py::test_x\n", [3]),
        ("pyproject.toml", '[tool.hatch.envs.default.env-vars]\nPYTEST_ADDOPTS = "--deselect a"\n', [2]),
        ("tox.ini", "[testenv:pytest-lint]\ncommands = flake8 --ignore=E501 src\n", []),
        ("spec/models/user_spec.rb", "RSpec.describe User, :focus do\n", [1]),
        ("spec/models/user_spec.rb", "RSpec.describe User, skip: 'later' do\n", [1]),
        ("spec/models/user_spec.rb", "RSpec.xdescribe User do\n", [1]),
        ("spec/features/pay_spec.rb", "  fscenario 'pays' do\n", [1]),
        ("spec/models/user_spec.rb", "    skip += 1\n    pending << order\n", []),
        ("pkg/a_test.go", "func n() int {\n\tif testing.Short() {\n\t\treturn 10\n\t}\n\treturn 100\n}\n", []),
        (
            "pkg/a_test.go",
            "func TestA(t *testing.T) {\n\t// a" + LS + "// b\n\tif testing.Short() {\n\t\treturn\n\t}\n}\n",
            [4],
        ),
        ("tests/conftest.py", "def pytest_configure(config):\n    setattr(config.option, 'keyword', 'not x')\n", [2]),
        ("tests/conftest.py", "setattr(config.option, name, 1)\nsetattr(obj, 'keyword', 1)\nsetattr()\n", []),
    ],
)
def test_round_two_forms(path: str, text: str, found: list[int]) -> None:
    assert lines(path, text) == found


@pytest.mark.parametrize(
    ("head", "after"),
    [
        (
            "import pytest\n\n\n@pytest.mark.parametrize('x', [\n    1,\n    pytest.param(2, marks=pytest.mark.xfail),\n])\n"
            "def test_a(x):\n    assert x\n",
            "import pytest\n\n\n@pytest.mark.parametrize('x', [\n    1,\n    pytest.param(2, marks=pytest.mark.xfail),\n"
            "    3,\n])\ndef test_a(x):\n    assert x\n",
        ),
        (
            "import pytest\n\npytestmark = [pytest.mark.skip]\n",
            "import pytest\n\npytestmark = [pytest.mark.skip, pytest.mark.slow]\n",
        ),
    ],
)
def test_a_case_added_beside_an_old_marked_element_is_old(tmp_path: Path, head: str, after: str) -> None:
    assert engine(tmp_path, "tests/test_a.py", head, after) == 0


def test_a_skip_moved_into_the_else_branch_is_new(tmp_path: Path) -> None:
    head = "import pytest\n\n\ndef test_a():\n    if WIN:\n        pytest.skip('x')\n"
    after = "import pytest\n\n\ndef test_a():\n    if WIN:\n        pass\n    else:\n        pytest.skip('x')\n"
    assert engine(tmp_path, "tests/test_a.py", head, after) == 1


def test_lines_split_as_python_reads_them_so_a_hidden_break_cannot_reuse_an_old_key(tmp_path: Path) -> None:
    head = "import pytest\n\nif WIN:\n    pytest.skip('x', allow_module_level=True)\n"
    after = (
        "import pytest\n\nx = 1  # pad\x1c\x1c\x1c\ns = '''\nif WIN:\n    pytest.skip('x', allow_module_level=True)'''\n"
        "if True:\n    pytest.skip('x', allow_module_level=True)\n"
    )
    assert engine(tmp_path, "tests/test_a.py", head, after) == 1


def test_a_marked_table_element_is_keyed_by_that_element() -> None:
    text = "import pytest\n\nCASES = [1, pytest.param(2,\n    marks=pytest.mark.xfail)]\n"
    (found,) = mod.findings({"event": "tool_use", "writes": {"tests/test_a.py": text}})
    assert found["key"] == "test-skip||CASES :: pytest.param(2, marks=pytest.mark.xfail)"


# Round 3 of the review.


@pytest.mark.parametrize(
    ("head", "after"),
    [
        (
            "import pytest\n\nA = [1, pytest.param(2, marks=pytest.mark.xfail)]\nB = [1, 2]\n",
            "import pytest\n\nA = [1, 2]\nB = [1, pytest.param(2, marks=pytest.mark.xfail)]\n",
        ),
        (
            "import pytest\n\nROWS = [pytest.param(1, marks=[pytest.mark.skip]), pytest.param(2)]\n",
            "import pytest\n\nROWS = [pytest.param(1), pytest.param(2, marks=[pytest.mark.skip])]\n",
        ),
        (
            "import pytest\n\nWIN_ONLY = [pytest.mark.skipif(sys.platform != 'win32', reason='x')]\n",
            "import pytest\n\npytestmark = [pytest.mark.skipif(sys.platform != 'win32', reason='x')]\n",
        ),
        (
            "import pytest\n\nROWS = (pytest.param(1, marks=pytest.mark.skip),)\nOTHER = ()\n",
            "import pytest\n\nROWS = ()\nOTHER = (pytest.param(1, marks=pytest.mark.skip),)\n",
        ),
        (
            "import pytest\n\nROWS = [pytest.param(1, marks=pytest.mark.skip)]\n",
            "import pytest\n\nROWS = [pytest.param(1, marks=pytest.mark.skip), pytest.param(1, marks=pytest.mark.skip)]\n",
        ),
    ],
)
def test_a_marked_row_moved_to_another_row_or_table_or_copied_is_new(tmp_path: Path, head: str, after: str) -> None:
    assert engine(tmp_path, "tests/test_a.py", head, after) == 1


def test_a_large_marked_table_is_judged_within_budget(tmp_path: Path) -> None:
    rows = "".join(f"    pytest.param({n}, 'é' * {n}, marks=pytest.mark.xfail),\n" for n in range(600))
    head = (
        "import pytest\n\n\n@pytest.mark.parametrize(('n', 's'), [\n" + rows + "])\ndef test_n(n, s):\n    assert n\n"
    )
    started = time.monotonic()
    assert engine(tmp_path, "tests/test_a.py", head, head.replace("    assert n\n", "    assert s is not None\n")) == 0
    assert time.monotonic() - started < 25


@pytest.mark.parametrize(
    ("path", "text", "found"),
    [
        ("pyproject.toml", '[ tool.pytest.ini_options ]\naddopts = "--deselect a"\n', [2]),
        ("pyproject.toml", '[tool."pytest".ini_options]\naddopts = "--deselect a"\n', [2]),
        ("src/a.test.js", "s.replace(/\\/*$/, '');\ntest.each([[1]]).skip('x', () => {});\n", [2]),
        ("src/a.test.js", "const q = /`/;\nconst r = a / b / c;\ntest.each([[1]]).skip('x', () => {});\n", [3]),
        ("src/a.test.js", "const q = /[/]\ntest.each([[1]]).skip('x', () => {});\n", [2]),
        ("spec/a_spec.rb", "  skip <<~MSG\n    later\n  MSG\n", [1]),
        ("spec/a_spec.rb", "  skip ||= 1\n", []),
        ("spec/a_spec.rb", "::RSpec.describe User, :focus do\n", [1]),
    ],
)
def test_round_three_forms(path: str, text: str, found: list[int]) -> None:
    assert lines(path, text) == found


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("ROWS: list = [pytest.param(1, marks=pytest.mark.skip)]\n", "ROWS :: pytest.param(1, marks=pytest.mark.skip)"),
        ("ROWS += [pytest.param(1, marks=pytest.mark.skip)]\n", "ROWS :: pytest.param(1, marks=pytest.mark.skip)"),
        ("run([pytest.param(1, marks=pytest.mark.skip)])\n", "Expr :: pytest.param(1, marks=pytest.mark.skip)"),
        (
            "@pytest.mark.parametrize('n', [pytest.param(\n    1, marks=pytest.mark.skip)])\ndef test_n(n):\n    pass\n",
            "test-skip|test_n|pytest.mark.parametrize('n') :: pytest.param( 1, marks=pytest.mark.skip)",
        ),
    ],
)
def test_a_row_is_named_with_what_owns_its_table(text: str, key: str) -> None:
    (found,) = mod.findings({"event": "tool_use", "writes": {"tests/test_a.py": "import pytest\n" + text}})
    assert found["key"].endswith(key)
