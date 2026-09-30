"""An expression engine that reaches request data runs whatever code the caller wrote."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-code-injection"

_FACTS = facts("java")["code_injection"]

_MESSAGE = (
    "This expression engine evaluates {source} as code, so the caller writes the program rather "
    "than a value -- arbitrary method calls, not a computed result. Evaluate a fixed expression "
    "the application wrote, or replace the engine with a lookup table keyed by a validated name. "
    f"An expression that must stay dynamic needs 'chock: allow {RULE_ID}' on this line, with the "
    "input checked against an allowlist first."
)


def _uses_an_expression_engine(text: FileText) -> bool:
    """This rule reads only files that import one of the named engines -- elsewhere .eval() and
    .evaluate() are ordinary method names this rule has no business judging."""
    return text.holds(*_FACTS["imports"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every engine evaluation a method body shows request data reaching, in a file that imports
    a scripting or expression-language engine."""
    if not _uses_an_expression_engine(text):
        return
    for flow in flows(text, _FACTS["sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Expression engine evaluating request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(evaluate): ScriptEngine|GroovyShell|Ognl|MVEL|ExpressionFactory over "
        "@RequestParam|@PathVariable|request.get* -- evaluate a fixed expression, or look the "
        "value up by a validated name instead of evaluating it"
    ),
    refuses=(
        "a `ScriptEngine.eval`, `GroovyShell.evaluate`, `Ognl.getValue`/`parseExpression`, "
        "`MVEL.eval`/`compileExpression`, or `ExpressionFactory.createValueExpression`/"
        "`createMethodExpression` a method body shows request data reaching, in a file that "
        "imports the engine"
    ),
    silent_on=(
        "the same call over a constant expression; the engine's import with no request data "
        "reaching it; the same file with no scripting or EL import at all"
    ),
    cwe=("CWE-95",),
    references=(
        "https://owasp.org/Top10/2021/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
    ),
)
