"""Explicitly turning a cookie's HttpOnly or Secure flag off strips the one thing that flag does."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.jakarta._config import not_spring

RULE_ID = "jakarta-insecure-cookie"

_FACTS = facts("jakarta")["cookie"]

_MESSAGE = (
    "This turns a cookie flag off explicitly: HttpOnly off lets JavaScript (and so an XSS "
    "payload) read the cookie, and Secure off lets it travel over plain HTTP. Set both to true "
    f"unless this cookie carries nothing sensitive, in which case put 'chock: allow {RULE_ID}' "
    "on this line and say so."
)


def _code_lines(text: FileText) -> Iterator[int]:
    for line_no, line in enumerate(text.lines, 1):
        if any(setter in line for setter in _FACTS["false_setters"]):
            yield line_no


def _web_xml_lines(text: FileText) -> Iterator[int]:
    if not text.holds(_FACTS["cookie_config_tag"]):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["web_xml_httponly_false"] in line or _FACTS["web_xml_secure_false"] in line:
            yield line_no


def scan(text: FileText) -> Iterator[Finding]:
    """Every explicit false flag, whether set in code or in a web.xml cookie-config."""
    if not not_spring(text):
        return
    if text.suffix in {".java", ".kt"}:
        for line_no in _code_lines(text):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)
    elif text.suffix == ".xml":
        for line_no in _web_xml_lines(text):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="Cookie flag turned off explicitly",
    suffixes=(".java", ".kt", ".xml"),
    scan=scan,
    constraint=(
        "never(disable): cookie.setHttpOnly(false)|cookie.setSecure(false)|web.xml "
        "<cookie-config> http-only|secure = false -- set both true unless the cookie is not sensitive"
    ),
    refuses="an explicit `setHttpOnly(false)`/`setSecure(false)`; web.xml cookie-config set false",
    silent_on="flags left true, or left unset; a cookie-config that sets neither to false; Spring code",
    cwe=("CWE-614", "CWE-1004"),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",),
)
