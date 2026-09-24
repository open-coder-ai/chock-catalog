"""A template's unescaped-output token writes a value into the page as markup."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-xss-unescaped-template"

_TOKENS = facts("templates")["unescaped_output"]

#: The escaping sibling each token opted out of -- beside the condition that names the token.
_SAFE_SIBLING = {
    "th:utext": "th:text",
    "[(${": "the escaped inline syntax [[${...}]]",
    "<%=": "<c:out>, or EL with the page's default escaping",
    'escapeXml="false"': 'the default escapeXml="true"',
    "escapeXml='false'": 'the default escapeXml="true"',
    'escape="false"': 'the default escape="true" (or omit the attribute)',
    "escape='false'": "the default escape='true' (or omit the attribute)",
    "?no_esc": "the default auto-escaping",
    "<#noescape>": "the default auto-escaping",
    "| raw": "the default auto-escaping (drop the raw filter)",
    "|raw": "the default auto-escaping (drop the raw filter)",
    "{{{": "{{ }} (double mustache), which escapes",
    "{{&": "{{ }} (double mustache), which escapes",
}


def _message(token: str) -> str:
    return (
        f"{token} writes this value into the page as markup rather than as text, so a value that "
        f"reaches it carries script. Use {_SAFE_SIBLING[token]}. Markup the application itself "
        f"produced, already sanitized, needs 'chock: allow {RULE_ID}' on this line."
    )


def scan(text: FileText) -> Iterator[Finding]:
    """Every unescaped-output token this template language spells."""
    tokens = _TOKENS.get(text.suffix, ())
    for line_no, line in enumerate(text.lines, 1):
        hit = next((token for token in tokens if token in line), None)
        if hit is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _message(hit))


RULE = Rule(
    id=RULE_ID,
    pack="templates",
    title="Unescaped template output",
    suffixes=tuple(_TOKENS),
    scan=scan,
    constraint=(
        'never(write): th:utext|[(${|<%=|escapeXml="false"|escape="false"|?no_esc|<#noescape>'
        "|raw|{{{|{{& "
        "-- these put a value into the page as markup; use the escaping sibling"
    ),
    refuses=(
        '`th:utext`, `[(${...})]`, `<%=`, `escapeXml="false"`, `escape="false"` (JSF), '
        "`?no_esc`, `<#noescape>`, `| raw` (Pebble), `{{{` / `{{&` (Mustache/Handlebars)"
    ),
    silent_on="the escaping sibling of each, and other `<% %>` forms",
    cwe=("CWE-79",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",),
)
