"""Calling proceed() on a TLS error hands every page load in this WebView to any man-in-the-middle."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "android-ssl-error-ignored"

_FACTS = facts("android")["ssl_error"]

_MESSAGE = (
    "This overrides onReceivedSslError and proceeds anyway, so an expired, self-signed or "
    "wrong-host certificate is accepted exactly like a good one -- the WebView's TLS check no "
    "longer protects anything it loads. Call handler.cancel() (the default WebViewClient already "
    "does this; remove the override) and fix the certificate instead of the check. A debug build "
    f"pinned to a known-bad certificate needs 'chock: allow {RULE_ID}' on this line."
)


def _method_blocks(lines: list[str]) -> Iterator[tuple[int, int]]:
    """(start index, end index) of every onReceivedSslError body, by brace depth from the line
    that names it to the line that closes it. A signature with no body -- an interface method,
    a call site merely mentioning the name -- never opens a block and is never yielded."""
    marker = _FACTS["method_marker"]
    index = 0
    while index < len(lines):
        if marker in lines[index]:
            depth = 0
            opened = False
            end = index
            while end < len(lines):
                depth += lines[end].count("{") - lines[end].count("}")
                if "{" in lines[end]:
                    opened = True
                if opened and depth <= 0:
                    break
                end += 1
            if opened:
                yield index, end
                index = end
        index += 1


def scan(text: FileText) -> Iterator[Finding]:
    """Every onReceivedSslError override whose body calls proceed() on the handler."""
    if _FACTS["method_marker"] not in text.text:
        return
    lines = text.lines
    for start, end in _method_blocks(lines):
        for line_no in range(start, end + 1):
            if _FACTS["proceed_call"] in lines[line_no]:
                yield Finding(RULE_ID, text.path, line_no + 1, lines[line_no], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="WebView TLS error proceeded through",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(proceed): handler.proceed() inside WebViewClient.onReceivedSslError -- "
        "call handler.cancel(), or remove the override entirely"
    ),
    refuses="`.proceed()` on the handler inside an `onReceivedSslError` override",
    silent_on="`.cancel()` inside the same override; a file that never overrides it",
    cwe=("CWE-295",),
    references=(
        "https://developer.android.com/reference/android/webkit/SslErrorHandler",
        "https://developer.android.com/privacy-and-security/security-ssl",
    ),
)
