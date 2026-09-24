"""Request data written straight to the servlet response body renders as HTML in the browser --
reflected XSS, one call away from a template engine that would have escaped it."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-xss-writer"

_FACTS = facts("java")["xss_writer"]

_MESSAGE = (
    "This response body is written from {source} with no template engine and no escaping in "
    "between, so a browser rendering it executes whatever script the caller sent -- reflected "
    "XSS. HTML-escape the value first (HtmlUtils.htmlEscape, StringEscapeUtils.escapeHtml4) or "
    f"set the content type to something a browser will not render as HTML. A value already "
    f"escaped needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every writer/output-stream print a method body shows request data reaching, unescaped."""
    for flow in flows(text, _FACTS["sinks"], sanitizers=tuple(_FACTS["sanitizers"])):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Response body written from request data, unescaped",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(call): response.getWriter().write|print|println or .getOutputStream().print "
        "built from @RequestParam|@PathVariable|request.get* with no HTML escaping in between"
    ),
    refuses="a getWriter()/getOutputStream() write/print/println a method body shows request data reaching",
    silent_on=(
        "the same value passed through HtmlUtils.htmlEscape/StringEscapeUtils.escapeHtml4/"
        "Encode.forHtml/ESAPI.encoder first; a constant or server-built response body"
    ),
    cwe=("CWE-79",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",),
)
