"""A session cookie sent without Secure or HttpOnly rides over plain HTTP, or is readable from
page script -- either way, the session id is no longer only the browser's to hold."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.spring._config import config_pairs, is_spring_config_file

_FACTS = facts("spring")["session_cookie"]

RULE_ID = "spring-insecure-session-cookie"

_PROPERTY_MESSAGE = (
    "`{key}` set to false lets this cookie {what}. Remove this line (the default is true), or set it "
    "back to true."
)
_JAVA_MESSAGE = (
    "This ResponseCookie is built with {what}. Set it true, or drop the call and keep the builder's"
    " own default."
)

_WHAT = {
    "secure": "travel over plain HTTP as well as HTTPS, so a network observer can read the session id",
    "http-only": "be read by page script, so a single XSS on this origin can steal the session id",
    "httponly": "be read by page script, so a single XSS on this origin can steal the session id",
}


def _what_for_key(key: str) -> str:
    last = key.rsplit(".", 1)[-1].lower()
    return _WHAT.get(last, _WHAT["secure"])


def _config_findings(text: FileText) -> Iterator[Finding]:
    if not is_spring_config_file(text.path):
        return
    for entry in config_pairs(text):
        if entry.key in _FACTS["properties_keys"] and entry.value.strip().lower() == "false":
            message = _PROPERTY_MESSAGE.format(key=entry.key, what=_what_for_key(entry.key))
            yield Finding(RULE_ID, text.path, entry.line_no, text.lines[entry.line_no - 1], message)


def _java_findings(text: FileText) -> Iterator[Finding]:
    lines = text.lines
    for line_no, line in enumerate(lines, 1):
        if _FACTS["response_cookie_open"] not in line:
            continue
        for offset in range(line_no - 1, min(line_no + 10, len(lines))):
            candidate = lines[offset]
            hit = next((call for call in _FACTS["insecure_calls"] if call in candidate), None)
            if hit is not None:
                what = "secure(false)" if "secure" in hit else "httpOnly(false)"
                yield Finding(
                    RULE_ID, text.path, offset + 1, candidate, _JAVA_MESSAGE.format(what=what)
                )
            if _FACTS["build_call"] in candidate and offset > line_no - 1:
                break


def scan(text: FileText) -> Iterator[Finding]:
    """Secure/HttpOnly turned false, in application config or a ResponseCookie builder chain."""
    if text.suffix in {".properties", ".yml", ".yaml"}:
        yield from _config_findings(text)
    elif text.suffix == ".java":
        yield from _java_findings(text)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Session cookie missing Secure or HttpOnly",
    suffixes=(".properties", ".yml", ".yaml", ".java"),
    scan=scan,
    constraint=(
        "never(set): server.servlet.session.cookie.{secure,http-only}=false, or "
        "ResponseCookie...secure(false)/httpOnly(false) -- keep both true"
    ),
    refuses="cookie.secure/http-only=false in config, and .secure(false)/.httpOnly(false) in a ResponseCookie chain",
    silent_on="the cookie flags left at their true default, and cookies built without ResponseCookie",
)
