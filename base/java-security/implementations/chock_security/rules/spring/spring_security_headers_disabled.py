"""Turning off the security headers block, or one header inside it, removes a browser-side
defense a request itself cannot ask for back."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "spring-security-headers-disabled"

_GUARD = facts("spring")["security_guard_tokens"]
_FACTS = facts("spring")["security_headers"]
_LAMBDA_PATTERNS = [re.compile(p) for p in _FACTS["lambda_disable"]]

_WHAT = {
    ".headers().disable()": "every security header this chain would send",
    "headers(AbstractHttpConfigurer::disable)": "every security header this chain would send",
    ".contentTypeOptions().disable()": "X-Content-Type-Options, so a browser may sniff a response into a"
    " different content type than it was served as",
    ".httpStrictTransportSecurity().disable()": "Strict-Transport-Security, so a browser may fall back to"
    " plain HTTP on a later visit",
    ".frameOptions().disable()": "X-Frame-Options, so this page can be framed and clickjacked",
}

_MESSAGE = "This disables {what}. Remove the disable() call; if one header must come off, keep the rest on."


def scan(text: FileText) -> Iterator[Finding]:
    """Every headers()/frameOptions()/contentTypeOptions()/HSTS disable, literal or lambda."""
    if not text.holds(*_GUARD):
        return
    for line_no, line in enumerate(text.lines, 1):
        hit = next((token for token in _FACTS["literal_disable"] if token in line), None)
        if hit is None and _FACTS["frame_options_disable"] in line:
            hit = _FACTS["frame_options_disable"]
        if hit is None:
            lambda_hit = next((p for p in _LAMBDA_PATTERNS if p.search(line)), None)
            if lambda_hit is not None:
                hit = ".headers().disable()" if "headers" in lambda_hit.pattern else ".frameOptions().disable()"
        if hit is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(what=_WHAT[hit]))


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Security response headers disabled",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(disable): headers().disable()|frameOptions().disable()|contentTypeOptions().disable()|"
        "httpStrictTransportSecurity().disable() -- keep the header on; drop only what must come off"
    ),
    refuses="headers()/frameOptions()/contentTypeOptions()/HSTS disable(), literal or lambda",
    silent_on="frameOptions().sameOrigin(), and files with no HttpSecurity",
)
