"""block-test-skips v2: the skip forms, test paths and runner configs HP07 adds, each shown refused and left alone."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import gatekit, scriptkit

mod = scriptkit.load("block-test-skips", "block-test-skips-gate.py")

# Concatenated where v1's line pattern would match, so this test file passes the gate installed in this repo.
AT_SKIP = "@pytest.mark." + "skip"
X_IT = "x" + "it("


def lines(path: str, text: str, event: str = "tool_use") -> list[int]:
    return [f["line"] for f in mod.findings({"event": event, "writes": {path: text}})]


def keys(path: str, text: str) -> list[str]:
    return [f["key"] for f in mod.findings({"event": "tool_use", "writes": {path: text}})]


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("tests/test_a.py", "pytest.skip('x')"),
        ("tests/test_a.py", "pytest.xfail('x')"),
        ("tests/test_a.py", "np = pytest.importorskip('numpy')"),
        ("tests/test_a.py", "self.skipTest('x')"),
        ("tests/test_a.py", "raise unittest.SkipTest('x')"),
        ("tests/test_a.py", "raise pytest.skip.Exception('x')"),
        ("tests/test_a.py", "pytestmark = pytest.mark.skipif(True, reason='x')"),
        ("tests/test_a.py", "case = pytest.param(1, marks=pytest.mark.xfail(run=False))"),
        ("tests/test_a.py", "later = unittest.expectedFailure"),
        ("tests/test_a.py", "later = getattr(self, 'skipTest')"),
        ("tests/test_a.py", "super().skipTest('x')"),
        ("tests/test_a.py", "item.add_marker(pytest.mark.xfail(strict=False))"),
        ("tests/test_a.py", "x = pytest.mark.xfail(strict=True, run=flag)"),
        ("src/a.test.ts", "test.todo('x');"),
        ("src/a.test.ts", "test.fixme('x', () => {});"),
        ("src/a.test.ts", "it.fails('x', () => {});"),
        ("src/a.test.ts", "test.skipIf(isCI)('x', () => {});"),
        ("src/a.test.ts", "it.concurrent.skip('x', async () => {});"),
        ("src/a.test.ts", "describe.skip.each([1])('x %i', () => {});"),
        ("src/a.test.ts", "xtest('x', () => {});"),
        ("src/a.test.ts", "fdescribe('x', () => {});"),
        ("src/a.test.ts", "  this.skip();"),
        ("cypress/e2e/pay.cy.js", "it." + "only('pays', () => {});"),
        ("playwright/pay.ts", "test.describe.fixme('pays', () => {});"),
        ("src/test/java/AppTest.java", "  @DisabledOnOs(OS.WINDOWS)"),
        ("src/test/java/AppTest.java", '  @EnabledIf("ready")'),
        ("src/test/java/AppTest.java", "    Assumptions.assumeTrue(ready);"),
        ("src/test/java/AppTest.java", "    assumeThat(x, is(1));"),
        ("src/test/java/AppTest.java", "  @Test(enabled = false)"),
        ("src/test/java/AppTest.java", '    throw new SkipException("x");'),
        ("app/AppTest.kt", "    @" + "Ignore"),
        ("app/src/test/kotlin/AppSpec.kt", 'class AppSpec : FunSpec({ test("x").config(enabled = false) { } })'),
        ("app/src/test/kotlin/App.kt", '  xtest("x") { }'),
        ("pkg/a_test.go", '\ts.T().Skip("x")'),
        ("src/lib.rs", "    #[ignore]"),
        ("tests/it.rs", "    #[cfg_attr(windows, ignore)]"),
        ("spec/a_spec.rb", "  " + X_IT + "'x') { }"),
        ("spec/a_spec.rb", "  fit 'x' do"),
        ("spec/a_spec.rb", "  pending 'later'"),
        ("spec/a_spec.rb", "  it 'x', :skip do"),
        ("spec/a_spec.rb", "  it 'x', focus: true do"),
        ("test/a_test.rb", "    skip(\"later\") unless ENV['CI']"),
        ("tests/FooTest.php", "        $this->markTestIncomplete();"),
        ("Tests/FooTests.cs", '    [Theory(Skip = "x")]'),
        ("Tests/FooTests.cs", "    [Explicit]"),
        ("Tests/FooTests.cs", "        Skip.If(ci);"),
        ("Tests/FooTests.cs", '        Assert.Inconclusive("x");'),
        ("Tests/FooTests.cs", "        Assume.That(ready);"),
        ("Tests/FooTests.swift", "        try XCTSkipIf(ci)"),
        ("Tests/FooTests.swift", '        XCTExpectFailure("x")'),
        ("Tests/FooTests.swift", '    @Test(.disabled("x")) func a() {}'),
        ("tests/test_a.py", "raise _pytest.outcomes.Skipped('x')"),
        ("src/a.test.ts", "xit.each([[1]])('x', () => {});"),
        ("src/a.test.ts", "fdescribe.each([1])('x', () => {});"),
        ("src/a.test.ts", "/**/ it." + "skip('x', () => {});"),
        ("src/a.test.ts", "it?.skip('x', () => {});"),
        ("src/a.test.ts", "it. skip('x', () => {});"),
        ("src/test/java/AppTest.java", "  @org.junit.jupiter.api.Disabled"),
        ("src/test/java/AppTest.java", '    throw new AssumptionViolatedException("x");'),
        ("src/lib.rs", "    # [ignore]"),
        ("Tests/FooTests.cs", '    [Xunit.Fact(Skip = "x")]'),
        ("Tests/FooTests.cs", '    [FactAttribute(Skip = "x")]'),
        ("Tests/FooTests.cs", '    [NUnit.Framework.Ignore("x")]'),
        ("Tests/FooTests.swift", "    @Test(.enabled(if: false)) func a() {}"),
        ("app/tests.py", "pytest.skip('x')"),
        ("src/MyApp.Tests/CalculatorFacts.cs", '    [Fact(Skip = "x")]'),
        ("spec/a_spec.rb", "  skip"),
        ("spec/a_spec.rb", "  scenario 'x', :pending do"),
        ("Spec/ThingSpec.lua", "  pending('x')  " + AT_SKIP),
    ],
)
def test_a_v2_form_in_a_test_file_is_refused(path: str, line: str) -> None:
    assert lines(path, f"first\n{line}\nlast\n") == [2]


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("tests/test_a.py", "x = pytest.mark.xfail(strict=True)"),
        ("tests/test_a.py", "x = pytest.mark.xfail(strict=True, run=True)"),
        ("tests/test_a.py", "skip = 3"),
        ("tests/test_a.py", "assert walk.skip(2)"),
        ("tests/test_a.py", "from pytest import skip"),
        ("tests/test_a.py", "assert 'pytest.skip()' in text"),
        ("tests/test_a.py", "x = getattr(obj, name)"),
        ("tests/test_a.py", "x = getattr(obj, 'name')"),
        ("tests/test_a.py", "x = pytest.raises(ValueError)"),
        ("tests/test_a.py", "x = f().skip"),
        ("src/a.test.ts", "expect(model.fit(data)).toBe(model);"),
        ("src/a.test.ts", "it('can skip and focus', () => {});"),
        ("src/a.test.ts", "const q = User.find().skip(10);"),
        ("src/a.test.ts", "context.fail('x');"),
        ("src/a.test.ts", "// it." + "only('x')"),
        ("src/test/java/AppTest.java", "  @Test void ready() { assertTrue(isEnabled()); }"),
        ("pkg/a_test.go", "\t// t." + 'Skip("x")'),
        ("src/lib.rs", "    // #[ignore]"),
        ("src/lib.rs", "#[serde(skip)]"),
        ("spec/a_spec.rb", "  it 'returns pending orders' do"),
        ("spec/a_spec.rb", "    expect(order.pending?).to be true"),
        ("spec/a_spec.rb", "    skip_count = 2"),
        ("spec/a_spec.rb", "  # skip 'later'"),
        ("tests/FooTest.php", "        $this->assertTrue($list->skip(1));"),
        ("Tests/FooTests.cs", "    [Fact]"),
        ("Tests/FooTests.swift", "    func testA() { XCTAssertTrue(ok) }"),
        ("src/app.rb", "  skip 'x'"),
        ("src/Thing.cs", '    [Fact(Skip = "x")]'),
        ("spec/models/order_spec.rb", "    create(:order, status: :pending)"),
        ("spec/models/order_spec.rb", "    expect(orders.select(&:pending?)).to eq([])"),
        ("spec/models/order_spec.rb", "    expect(counts).to eq(pending: 1, done: 2)"),
        ("spec/models/order_spec.rb", "    described_class.new(skip: 2)"),
        ("spec/models/order_spec.rb", "    expect(pending).to eq 0"),
        ("spec/factories/orders.rb", "    status { :pending }"),
        ("spec/a_spec.rb", "  it 'x', skip: false do"),
        ("pkg/a_test.go", "\tif err := d.Skip(); err != nil {"),
        ("src/a.test.ts", "context.skip = true;"),
        ("app/AppTest.kt", "@IgnoreExtraProperties"),
        ("Tests/ViewTests.swift", '    let b = Button("x").disabled(true)'),
        ("tests/data.json", '{"skip": true}'),
    ],
)
def test_ordinary_code_and_other_files_are_left_alone(path: str, line: str) -> None:
    assert lines(path, f"{line}\n") == []


@pytest.mark.parametrize(
    "path",
    ["spec/a.rb", "Spec/A.swift", "Tests/a.cs", "e2e/a.ts", "cypress/a.js", "playwright/a.ts", "web/a.spec.vue"],
)
def test_the_wider_test_paths_are_judged(path: str) -> None:
    assert mod.kind_of(path) is not None


@pytest.mark.parametrize("path", ["inspect/a.rb", "src/Spectrum.swift", "latest/a.cs", "src/e2e.ts", "docs/a.md"])
def test_paths_outside_the_test_trees_are_not(path: str) -> None:
    assert mod.kind_of(path) is None


def test_python_aliases_resolve_through_imports() -> None:
    text = (
        "import pytest as pt\nimport unittest.mock\nfrom unittest import skip as later\nfrom pytest import mark\n"
        "a = pt.skip\nb = later\nc = mark.skipif\nd = unittest.mock\n"
    )
    assert lines("tests/test_a.py", text) == [5, 6, 7]


def test_a_python_file_that_does_not_parse_is_read_as_text() -> None:
    text = "def (:\n    pytest.skip('x')\n# pytest.skip\ncollect_ignore = [\n"
    assert lines("tests/test_a.py", text) == [2, 4]


def test_collect_ignore_is_keyed_per_entry() -> None:
    text = "collect_ignore = ['a.py']\ncollect_ignore.append('b.py')\ncollect_ignore_glob += names\nx = 1\n"
    assert keys("conftest.py", text) == [
        "test-config||collect_ignore|a.py",
        "test-config||collect_ignore|b.py",
        "test-config||collect_ignore_glob += names",
    ]


def test_the_collection_hooks_that_drop_tests_are_refused() -> None:
    text = (
        "def pytest_ignore_collect(collection_path, config):\n    return True\n\n\n"
        "def pytest_collection_modifyitems(session, config, items):\n"
        "    items.remove(items[0])\n    del items[1]\n    items[0] += 1\n    items.sort()\n    config.option.x = 1\n"
        "    print(items)\n\n\ndef other(items):\n    items.clear()\n"
    )
    assert lines("tests/conftest.py", text) == [1, 6, 7, 8]


def test_pytest_options_that_hide_tests_are_refused() -> None:
    text = (
        "[pytest]\naddopts =\n    --ignore=tests/slow\n    --ignore-glob=*_slow.py\n    -k 'a and not b'\n"
        "# --deselect x\n; --deselect y\n    -m 'not slow'\n    --ignore-installed\n"
    )
    assert lines("pytest.ini", text) == [3, 4, 5]
    assert lines("setup.cfg", "[tool:pytest]\naddopts = --deselect a\n") == [2]


def test_jest_ignore_patterns_are_keyed_per_entry() -> None:
    text = (
        "// testPathIgnorePatterns: ['/old/'],\nmodule.exports = {\n  testPathIgnorePatterns: ['/node_modules/',"
        " \"/a[)]/\",\n    `/b/`],\n  modulePathIgnorePatterns: ['/c/'],\n  other: { testPathIgnorePatterns: ignored },\n};\n"
    )
    assert keys("jest.config.js", text) == [
        "test-config||testPathIgnorePatterns|/a[)]/",
        "test-config||testPathIgnorePatterns|/b/",
        "test-config||other: { testPathIgnorePatterns: ignored },",
    ]


def test_a_jest_list_that_is_not_all_strings_is_one_finding() -> None:
    assert keys("package.json", '{"jest": {"testPathIgnorePatterns": ["/a/", ...more]}}') == [
        "test-config||testPathIgnorePatterns|/a/",
        'test-config||testPathIgnorePatterns|["/a/", ...more]',
    ]
    assert keys("jest.config.json", '{"testPathIgnorePatterns": ["/a/", "/b') == [
        "test-config||testPathIgnorePatterns|/",
        "test-config||testPathIgnorePatterns|/a/",
    ]


def test_an_escaped_quote_does_not_end_a_jest_pattern() -> None:
    text = "module.exports = { testPathIgnorePatterns: ['/q\\'s/'] };"
    assert keys("jest.config.js", text) == ["test-config||testPathIgnorePatterns|/q\\'s/"]


def test_a_jest_table_is_matched_as_a_group() -> None:
    text = (
        "it.each([[1, ')'], [2]])('n', () => {});\ntest.each`\n  a\n  ${1}\n`.only('t', () => {});\n"
        "test.each([\n  [1],\n]).skip('t', () => {});\ndescribe.each(['x'])\n"
    )
    assert lines("src/a.test.ts", text) == [5, 8]
    assert lines("src/a.test.ts", "test.each`a") == []


def test_a_waiver_on_each_config_line_is_honoured_at_commit() -> None:
    waived = "[pytest]\naddopts = --deselect a  # chock: allow test-skip -- OPS-1\n"
    assert lines("pytest.ini", waived, event="commit") == []
    assert lines("pytest.ini", waived) == [2]


def test_the_scope_names_annotated_rust_and_csharp_tests() -> None:
    rust = "mod tests {\n    #[test]\n    #[ignore]\n    fn slow() {}\n}\n"
    csharp = 'public class T {\n    [Fact(Skip = "x")]\n    public void Slow() {}\n}\n'
    assert keys("src/lib.rs", rust) == ["test-skip|tests.slow|#[ignore]"]
    assert keys("Tests/TTests.cs", csharp) == ['test-skip|T.Slow|[Fact(Skip = "x")]']


def test_an_added_jest_ignore_pattern_is_refused_and_an_old_one_moved_is_not(tmp_path: Path) -> None:
    head = "module.exports = { testPathIgnorePatterns: ['/a/'] };\n"
    repo = scriptkit.init_repo(tmp_path / "r", {"jest.config.js": head})
    moved = "module.exports = {\n  verbose: true,\n  testPathIgnorePatterns: [\n    '/a/',\n  ],\n};\n"
    assert gatekit.judge("block-test-skips", repo, gatekit.PRE_TOOL_USE, {"jest.config.js": moved})[0] == 0
    wider = moved.replace("'/a/',", "'/a/', '/b/',")
    code, err = gatekit.judge("block-test-skips", repo, gatekit.PRE_TOOL_USE, {"jest.config.js": wider})
    assert code == 1
    assert "jest.config.js:4" in err
