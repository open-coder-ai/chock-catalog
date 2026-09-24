"""Turning off a template engine's auto-escaping writes every value in as raw markup, everywhere."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "templates-autoescape-disabled"

_FACTS = facts("templates")["autoescape_disabled"]

_MESSAGE = (
    "{token} turns off this engine's auto-escaping, so every value any template writes -- not "
    "just this one -- goes into the page as raw markup. Leave auto-escaping on and mark the rare "
    "value that is already-sanitized markup at that call site instead. A template set that must "
    f"disable it needs 'chock: allow {RULE_ID}' on this line and a review of every value it writes."
)


def scan(text: FileText) -> Iterator[Finding]:
    """The engine-level switch that turns escaping off for every template the engine renders."""
    if text.suffix == ".java":
        for entry in _FACTS["java_tokens"]:
            if not text.holds(*entry["markers"]):
                continue
            for line_no, line in enumerate(text.lines, 1):
                if entry["token"] in line:
                    yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(token=entry["token"]))
    else:
        for line_no, line in enumerate(text.lines, 1):
            hit = next((t for t in _FACTS["ftlh_tokens"] if t in line), None)
            if hit is not None:
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(token=hit))


RULE = Rule(
    id=RULE_ID,
    pack="templates",
    title="Template engine auto-escaping disabled",
    suffixes=(".java", ".ftlh"),
    scan=scan,
    constraint=(
        "never(disable): Pebble .autoEscaping(false)|Handlebars EscapingStrategy.NOOP|"
        "FreeMarker setOutputFormat(PlainTextOutputFormat.INSTANCE)|"
        'setAutoEscapingPolicy(DISABLE_AUTO_ESCAPING_POLICY)|.ftlh output_format="plainText"|'
        "auto_esc=false -- leave auto-escaping on; mark the rare safe value at its call site"
    ),
    refuses=(
        "Pebble `.autoEscaping(false)`, Handlebars `EscapingStrategy.NOOP`, FreeMarker "
        "`setOutputFormat(PlainTextOutputFormat.INSTANCE)`/`setAutoEscapingPolicy(Configuration."
        'DISABLE_AUTO_ESCAPING_POLICY)`, or `.ftlh` `output_format="plainText"`/`auto_esc=false`'
    ),
    silent_on=(
        "any of these method names in a file that never imports that template engine, and a "
        "`.ftlh` file that never sets those directives"
    ),
    cwe=("CWE-79", "CWE-116"),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",),
)
