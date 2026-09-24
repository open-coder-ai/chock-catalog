"""A @Test method that never asserts, verifies or expects anything passes whether the code under
test works or not -- it only proves the method didn't throw, which most bugs don't make it do."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.testing._util import holds, is_test_path
from chock_security.source import code

RULE_ID = "testing-no-assertion"

_FACTS = facts("testing")
#: `@Test` but not `@TestInstance` or `@TestConfiguration`: those annotate a class, not a test.
_ANNOTATION = re.compile("(?:" + "|".join(re.escape(a) for a in _FACTS["test_annotations"]) + r")(?!\w)")
#: An assertion is any call named like one -- JUnit, AssertJ (`assertThatThrownBy`), Mockito
#: (`verifyNoInteractions`), Truth, a team's own `assertValidOrder` helper -- or a BDD `then(`
#: or Awaitility `await(`. Reading too much as an assertion only keeps the rule silent.
_ASSERTION = re.compile(
    r"\b(?:"
    + "|".join(_FACTS["assertion_call_prefixes"])
    + r")\w*\s*\("
    + "|"
    + "|".join(r"\b" + re.escape(c) for c in _FACTS["assertion_bare_calls"])
)

_MESSAGE = (
    "This test method has no assertion, verification or expected-exception check, so it passes "
    "whether the code under test is right or not. Add an assertThat/assertEquals/verify/"
    "assertThrows call, or an `expected` on @Test, that actually checks something."
)


def _body_text(lines: list[str], start: int) -> str | None:
    """The text of the braced block that follows line `start`, or None if none is ever opened."""
    depth = 0
    opened = False
    collected: list[str] = []
    for idx in range(start, len(lines)):
        line = lines[idx]
        if not opened:
            if "{" not in line:
                continue
            opened = True
            rest = line.split("{", 1)[1]
            depth = 1 + rest.count("{") - rest.count("}")
            collected.append(rest)
        else:
            depth += line.count("{") - line.count("}")
            collected.append(line)
        if depth <= 0:
            return "\n".join(collected)
    return None


def scan(text: FileText) -> Iterator[Finding]:
    """Every @Test-family method, in a test file, whose body holds no known assertion call and
    whose annotation carries no `expected =` (the JUnit4 expected-exception form)."""
    if not is_test_path(text.path, _FACTS["test_path"]):
        return
    lines = code(text)
    for line_no, line in enumerate(lines):
        if not _ANNOTATION.search(line):
            continue
        body = _body_text(lines, line_no + 1)
        if body is None:
            continue
        if "expected" in line or _ASSERTION.search(body) or holds(body, _FACTS["assertion_markers"]):
            continue
        yield Finding(RULE_ID, text.path, line_no + 1, text.lines[line_no], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="testing",
    title="Test with no assertion",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(write): @Test method with no assertThat/assertEquals/verify/assertThrows/... call and no @Test(expected=...)",
    refuses="an @Test/@ParameterizedTest/@RepeatedTest method whose body calls nothing from JUnit, AssertJ, Hamcrest, Mockito, MockMvc or StepVerifier that checks a value",
    silent_on="a test calling anything named assert*/verify*/expect*/fail*/should*/check*, a BDD then() or await(), .andExpect/StepVerifier; `@Test(expected = SomeException.class)` with no assertion; the same empty method outside a test file",
    references=(
        "https://rules.sonarsource.com/java/RSPEC-2699/",
        "https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html#unittestshouldincludeassert",
    ),
)
