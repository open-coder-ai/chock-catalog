"""Compiling a template from request data lets the caller write template syntax, not just a value."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "templates-ssti-request-template"

_ENGINES = facts("templates")["ssti"]["engines"]

_MESSAGE = (
    "This compiles a template from {source}, so whoever controls it can write template syntax "
    "that runs on the server -- a classic template turns into remote code execution. Load a "
    "fixed, pre-compiled template by name and pass only data into it, never the template text "
    f"itself. A template that must stay dynamic needs 'chock: allow {RULE_ID}' on this line and a "
    "review of exactly what syntax it can contain."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every template-compiling sink whose engine this file shows configured, request data reaching it."""
    if text.suffix != ".java":
        return
    for engine in _ENGINES:
        if not text.holds(*engine["markers"]):
            continue
        for flow in flows(text, [engine["sink"]]):
            yield Finding(RULE_ID, text.path, flow.line_no, flow.line, _MESSAGE.format(source=flow.source))


RULE = Rule(
    id=RULE_ID,
    pack="templates",
    title="Template compiled from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(compile): FreeMarker new Template(...)|Velocity.evaluate(...)|"
        "templateEngine.process(...) with a StringTemplateResolver|Pebble "
        "engine.getLiteralTemplate(...)|Mustache compiler().compile(new StringReader(...))|"
        "Handlebars.compileInline(...)|Jinjava.render(...) reaching request data "
        "-- load a fixed template by name; pass only data in"
    ),
    refuses=(
        "a method body showing request data reaching FreeMarker `new Template(`/"
        "`StringTemplateLoader.putTemplate(`, Velocity `evaluate(`/`RuntimeSingleton.parse(`, "
        "Thymeleaf `templateEngine.process(` when the file also configures a "
        "`StringTemplateResolver`, Pebble `engine.getLiteralTemplate(`, Mustache "
        "`compiler().compile(new StringReader(`, `Handlebars.compileInline(`, or Jinjava `render(`"
    ),
    silent_on=(
        "a fixed template string; loading a template by name (`getTemplate(`) rather than "
        "compiling text; Thymeleaf `process(` with no `StringTemplateResolver` in the file; "
        "and a file that never configures one of these engines"
    ),
)
