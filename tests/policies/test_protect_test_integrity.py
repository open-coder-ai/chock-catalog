"""protect-test-integrity: the declarative test_integrity gate's three regexes, held to samples."""

from __future__ import annotations

import re

import pytest
from policies import scriptkit

PARAMS = scriptkit.manifest("protect-test-integrity")["hook"]["gate"]["params"]
PATH = re.compile(PARAMS["test_path_regex"])
ASSERTION = re.compile(PARAMS["assertion_pattern"])
DUMMY = re.compile(PARAMS["dummy_assertion_pattern"])
PRAGMA = re.compile(PARAMS["allowlist_pragma"])


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_a.py",
        "test/a.rb",
        "pkg/tests/unit/x.py",
        "test_a.py",
        "src/test_helpers.py",
        "src/a_test.py",
        "pkg/a_test.go",
        "web/a.test.ts",
        "web/a.spec.js",
        "web/a.test.mjs",
        "web/a.spec.tsx",
        "web/__tests__/a.js",
        "src/test/java/com/x/AppTest.java",
        "app/src/test/kotlin/A.kt",
    ],
)
def test_test_layouts_are_recognised(path: str) -> None:
    assert PATH.search(path)


@pytest.mark.parametrize(
    "path",
    [
        "src/app.py",
        "src/contest/a.py",
        "src/latest/a.py",
        "src/attest.py",
        "docs/testing.md",
        "src/a.test.txt",
        "src/testing/a.py",
        "src/main/java/App.java",
        "src/test.py",
    ],
)
def test_ordinary_source_is_not_a_test(path: str) -> None:
    assert not PATH.search(path)


@pytest.mark.parametrize(
    "line",
    [
        "    assert x == 1",
        "    self.assertEqual(a, b)",
        "    assert_eq!(a, b)",
        "    expect(x).toBe(1)",
        "    x.should.equal(1)",
        "    require.NoError(t, err)",
        "    with pytest.raises(ValueError):",
        '    t.Errorf("bad")',
        '    t.Fatal("bad")',
        "    assertThat(x).isTrue()",
        "    Assert.assertTrue(ok)",
        "    assert(x)",
        "    assert.equal(a, b)",
        "    assert",
    ],
)
def test_assertions_are_counted(line: str) -> None:
    assert ASSERTION.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "    x = compute()",
        "    print('assertive')",
        "    t.Log('x')",
        "    # expects",
        "    # asserts the thing",
        "    x = 'assertion'",
    ],
)
def test_other_lines_are_not_assertions(line: str) -> None:
    assert not ASSERTION.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "    assert True",
        "    assert 1",
        "    assert True, 'placeholder'",
        "    assert True  # todo",
        "    self.assertTrue(True)",
        "    Assertions.assertTrue(true);",
        '    assertTrue(true, "x");',
        "    expect(true).toBe(true);",
        "    expect(true).toBeTruthy();",
        "    expect(1).toBe(1);",
    ],
)
def test_vacuous_assertions_are_recognised(line: str) -> None:
    assert DUMMY.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "    assert True == flag",
        "    assert 1 == count",
        "    assert value is True",
        "    assertTrue(trueish)",
        "    assertTrue(true_count > 0)",
        "    expect(true_count).toBe(1)",
        "    expect(isReady()).toBe(true)",
        "    # assert True",
    ],
)
def test_real_assertions_that_mention_true_are_not_vacuous(line: str) -> None:
    assert not DUMMY.search(line)


def test_the_waiver_pragma() -> None:
    assert PRAGMA.search("# chock: allow test-integrity -- reason")
    assert PRAGMA.search("// chock:allow  test-integrity")
    assert not PRAGMA.search("# chock: allow test-skip")


def test_the_gate_is_bound_at_commit_and_tool_use() -> None:
    gate = scriptkit.manifest("protect-test-integrity")["hook"]["gate"]
    assert gate["kind"] == "test_integrity"
    assert gate["on"] == ["commit", "tool_use"]
