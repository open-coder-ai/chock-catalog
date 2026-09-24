"""Cases for the testing pack: Tests.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

NO_ASSERTION = "testing-no-assertion"
THREAD_SLEEP = "testing-thread-sleep"
DISABLED_WITHOUT_REASON = "testing-disabled-without-reason"
ASSERTTRUE_EQUALITY = "testing-asserttrue-equality"
ASSERTFALSE_EQUALS = "testing-assertfalse-equals"
ASSERTEQUALS_LITERAL_ACTUAL = "testing-assertequals-literal-actual"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # testing-no-assertion
    (
        NO_ASSERTION,
        "src/test/java/com/acme/CalculatorTest.java",
        "class CalculatorTest {\n  @Test\n  public void addsNumbers() {\n  }\n}\n",
        [2],
    ),
    (
        NO_ASSERTION,
        "src/test/java/com/acme/CalculatorTest.java",
        "class CalculatorTest {\n  @ParameterizedTest\n  public void addsNumbers(int a) {\n    Calculator.add(a, 1);\n  }\n}\n",
        [2],
    ),
    (
        NO_ASSERTION,
        "src/test/java/com/acme/CalculatorTest.java",
        "class CalculatorTest {\n  @Test\n  public void triggersProcessing() {\n    service.process();\n  }\n}\n",
        [2],
    ),
    (
        NO_ASSERTION,
        "src/test/java/com/acme/CalculatorTest.java",
        "class CalculatorTest {\n  @Test\n  public void addsNumbers() {\n    int result = Calculator.add(2, 3);\n    assertEquals(5, result);\n  }\n}\n",
        [],
    ),
    (
        NO_ASSERTION,
        "src/test/java/com/acme/CalculatorTest.java",
        "class CalculatorTest {\n  @Test(expected = IllegalArgumentException.class)\n  public void rejectsNegative() {\n    Calculator.add(-1, -1);\n  }\n}\n",
        [],
    ),
    (
        # is_test_path False: the same empty test method outside a test file is not this rule's business.
        NO_ASSERTION,
        "src/main/java/com/acme/Calculator.java",
        "class Calculator {\n  @Test\n  public void addsNumbers() {\n  }\n}\n",
        [],
    ),
    (
        # a bare, dangling annotation with no method following it: _body_text finds no brace to
        # open, so there is nothing to analyze and the rule stays silent rather than guessing.
        NO_ASSERTION,
        "src/test/java/com/acme/WeirdTest.java",
        "@Test\n",
        [],
    ),
    # testing-thread-sleep
    (
        THREAD_SLEEP,
        "FooTest.java",
        "class FooTest {\n  @Test\n  void waitsForIt() {\n    Thread.sleep(500);\n  }\n}\n",
        [4],
    ),
    (
        THREAD_SLEEP,
        "src/test/java/com/acme/BarTest.java",
        "class BarTest {\n  @Test\n  void waitsForIt() {\n    Thread.sleep(delay);\n  }\n}\n",
        [4],
    ),
    (
        THREAD_SLEEP,
        "src/test/java/com/acme/BarIT.java",
        "class BarIT {\n  @Test\n  void waitsTwice() {\n    Thread.sleep(100);\n    Thread.sleep(200);\n  }\n}\n",
        [4, 5],
    ),
    (
        THREAD_SLEEP,
        "src/main/java/com/acme/Poller.java",
        "class Poller {\n  void waitForIt() throws Exception {\n    Thread.sleep(1000);\n  }\n}\n",
        [],
    ),
    (
        THREAD_SLEEP,
        "src/test/java/com/acme/BazTest.java",
        "class BazTest {\n  @Test\n  void waitsForIt() {\n    // Thread.sleep(500);\n  }\n}\n",
        [],
    ),
    (
        THREAD_SLEEP,
        "src/test/java/com/acme/QuxTest.java",
        "class QuxTest {\n  @Test\n  void waitsForIt() {\n    await().atMost(5, SECONDS).until(ready::get);\n  }\n}\n",
        [],
    ),
    # testing-disabled-without-reason
    (
        DISABLED_WITHOUT_REASON,
        "src/test/java/com/acme/FooTest.java",
        "class FooTest {\n  @Disabled\n  @Test\n  void skipped() {}\n}\n",
        [2],
    ),
    (
        DISABLED_WITHOUT_REASON,
        "src/test/java/com/acme/FooTest.java",
        "class FooTest {\n  @Ignore()\n  @Test\n  void skipped() {}\n}\n",
        [2],
    ),
    (
        DISABLED_WITHOUT_REASON,
        "src/test/java/com/acme/FooTest.java",
        'class FooTest {\n  @Disabled(" ")\n  @Test\n  void skipped() {}\n}\n',
        [2],
    ),
    (
        DISABLED_WITHOUT_REASON,
        "src/test/java/com/acme/FooTest.java",
        'class FooTest {\n  @Disabled("flaky, see JIRA-123")\n  @Test\n  void skipped() {}\n}\n',
        [],
    ),
    (
        DISABLED_WITHOUT_REASON,
        "src/test/java/com/acme/FooTest.java",
        'class FooTest {\n  @Ignore("known bug JIRA-456")\n  @Test\n  void skipped() {}\n}\n',
        [],
    ),
    (
        DISABLED_WITHOUT_REASON,
        "FooTest.java",
        "class FooTest {\n  @Test\n  void works() {\n    assertTrue(true);\n  }\n}\n",
        [],
    ),
    (
        # is_test_path False: this rule's own annotations only mean something in test files.
        DISABLED_WITHOUT_REASON,
        "src/main/java/com/acme/Foo.java",
        "class Foo {\n  @Disabled\n  void skipped() {}\n}\n",
        [],
    ),
    (
        # near miss: a bare @Disabled mentioned in a comment is not an annotation.
        DISABLED_WITHOUT_REASON,
        "src/test/java/com/acme/FooTest.java",
        "class FooTest {\n  // @Disabled\n  @Test\n  void works() {}\n}\n",
        [],
    ),
    # testing-asserttrue-equality
    (ASSERTTRUE_EQUALITY, "FooTest.java", "assertTrue(actual.equals(expected));\n", [1]),
    (ASSERTTRUE_EQUALITY, "FooTest.java", "assertTrue(count == 3);\n", [1]),
    (ASSERTTRUE_EQUALITY, "FooTest.java", "assertTrue(a.equals(b) && flag);\n", [1]),
    (ASSERTTRUE_EQUALITY, "FooTest.java", "assertEquals(expected, actual);\n", []),
    (ASSERTTRUE_EQUALITY, "FooTest.java", "assertTrue(list.isEmpty());\n", []),
    (ASSERTTRUE_EQUALITY, "FooTest.java", "assertTrue(user.isActive());\n", []),
    # testing-assertfalse-equals
    (ASSERTFALSE_EQUALS, "FooTest.java", "assertFalse(actual.equals(expected));\n", [1]),
    (ASSERTFALSE_EQUALS, "FooTest.java", 'assertFalse(user.getName().equals("admin"));\n', [1]),
    (ASSERTFALSE_EQUALS, "FooTest.java", "assertFalse(a.equals(b) || flag);\n", [1]),
    (ASSERTFALSE_EQUALS, "FooTest.java", "assertNotEquals(expected, actual);\n", []),
    (ASSERTFALSE_EQUALS, "FooTest.java", "assertFalse(list.isEmpty());\n", []),
    (ASSERTFALSE_EQUALS, "FooTest.java", "assertFalse(count == 0);\n", []),
    # testing-assertequals-literal-actual
    (ASSERTEQUALS_LITERAL_ACTUAL, "FooTest.java", "assertEquals(result, 42);\n", [1]),
    (ASSERTEQUALS_LITERAL_ACTUAL, "FooTest.java", 'assertEquals(computedTotal, "5");\n', [1]),
    (ASSERTEQUALS_LITERAL_ACTUAL, "FooTest.java", "assertNotEquals(userId, 7);\n", [1]),
    (ASSERTEQUALS_LITERAL_ACTUAL, "FooTest.java", "assertEquals(42, result);\n", []),
    (ASSERTEQUALS_LITERAL_ACTUAL, "FooTest.java", "assertEquals(expected, actual);\n", []),
    (ASSERTEQUALS_LITERAL_ACTUAL, "FooTest.java", "assertEquals(1, 2);\n", []),
    (
        # near miss: a nested call on either side is outside this regex's simple two-argument
        # shape, so it is left alone rather than risking a wrong guess about which side is which.
        ASSERTEQUALS_LITERAL_ACTUAL,
        "FooTest.java",
        'assertEquals(total(), "5");\n',
        [],
    ),
]

#: Assertions named the way real suites name them, and class-level annotations that are not tests.
_T = "src/test/java/com/acme/OrderTest.java"
CASES += [
    (
        "testing-no-assertion",
        _T,
        "@Test\nvoid a() {\n  assertThatThrownBy(() -> svc.run()).isInstanceOf(X.class);\n}\n",
        [],
    ),
    ("testing-no-assertion", _T, "@Test\nvoid a() {\n  svc.run();\n  verifyNoInteractions(repo);\n}\n", []),
    ("testing-no-assertion", _T, "@Test\nvoid a() {\n  assertValidOrder(svc.place());\n}\n", []),
    ("testing-no-assertion", _T, "@Test\nvoid a() {\n  then(repo).should().save(order);\n}\n", []),
    ("testing-no-assertion", _T, "@Test\nvoid a() {\n  await().atMost(ofSeconds(5)).until(done::get);\n}\n", []),
    ("testing-no-assertion", _T, "@TestInstance(PER_CLASS)\nclass OrderTest {\n  void helper() { build(); }\n}\n", []),
    ("testing-no-assertion", _T, "@Test\nvoid a() {\n  checkout.run();\n  thenable.run();\n}\n", [1]),
]
