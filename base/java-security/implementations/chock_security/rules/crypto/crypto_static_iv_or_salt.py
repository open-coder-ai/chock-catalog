"""Reusing an IV or salt across encryptions defeats the property the mode relies on for security."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import methods
from chock_security.pack import Rule, facts

RULE_ID = "crypto-static-iv-or-salt"

_FACTS = facts("crypto")["iv_salt"]

#: A literal byte array (has values) or a string turned into bytes, passed straight into the
#: constructor -- as opposed to a variable, which the array-tracking check below handles.
_INLINE_LITERAL = re.compile(
    r"new\s+(?:IvParameterSpec|GCMParameterSpec|PBEKeySpec)\("
    r"[^)]*(?:\"[^\"]*\"\.getBytes\(|new\s+byte\[\]\s*\{[^}]*\d)"
)
_FIXED_ARRAY_DECL = re.compile(r"\bbyte\[\]\s*(\w+)\s*=\s*new\s+byte\[\d+\]\s*;")

_MESSAGE_LITERAL = (
    "This {kind} is a fixed literal, so every message this key ever encrypts reuses it -- for "
    "GCM that breaks confidentiality outright, and for CBC it makes identical plaintext prefixes "
    "detectable. Generate it fresh per encryption with SecureRandom.nextBytes(). A fixture that "
    f"only exists for a test vector needs 'chock: allow {RULE_ID}' on this line."
)
_MESSAGE_UNFILLED = (
    "{name} is allocated but nothing in this method fills it from SecureRandom before it is used "
    "as {kind} on this line, so it stays all zero -- as static as a literal. Call "
    "SecureRandom.nextBytes({name}) before this line, or generate {name} from it directly."
)


def _kind_of(call_text: str) -> str:
    if "IvParameterSpec" in call_text:
        return "IV"
    if "GCMParameterSpec" in call_text:
        return "GCM nonce"
    return "salt"


def _literal_findings(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(text.lines, 1):
        match = _INLINE_LITERAL.search(line)
        if match:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE_LITERAL.format(kind=_kind_of(match.group(0))))


def _unfilled_array_findings(text: FileText) -> Iterator[Finding]:
    for method in methods(text):
        body_lines = [line for _, line in method.body]
        declared = {m.group(1) for line in body_lines for m in [_FIXED_ARRAY_DECL.search(line)] if m}
        for name in declared:
            filled = any(re.search(rf"\.nextBytes\(\s*{re.escape(name)}\s*\)", line) for line in body_lines)
            if filled:
                continue
            for line_no, line in method.body:
                used = re.search(
                    rf"new\s+(?:IvParameterSpec|GCMParameterSpec|PBEKeySpec)\([^)]*\b{re.escape(name)}\b", line,
                )
                if used:
                    yield Finding(
                        RULE_ID, text.path, line_no, line,
                        _MESSAGE_UNFILLED.format(name=name, kind=_kind_of(used.group(0))),
                    )


def scan(text: FileText) -> Iterator[Finding]:
    """A literal IV/nonce/salt, or a fixed-size array never filled by SecureRandom before use."""
    yield from _literal_findings(text)
    yield from _unfilled_array_findings(text)


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Static IV, nonce, or salt",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        'never(construct): IvParameterSpec|GCMParameterSpec|PBEKeySpec from a literal '
        '"...".getBytes()/byte[]{...}, or a `new byte[N]` never filled by SecureRandom.nextBytes '
        "in the same method -- fill it with SecureRandom.nextBytes() first"
    ),
    refuses=(
        "an IvParameterSpec/GCMParameterSpec/PBEKeySpec built from a literal string or byte array, "
        "or from a fixed-size array the method never fills with SecureRandom.nextBytes"
    ),
    silent_on="the same array filled by SecureRandom.nextBytes(...) earlier in the method",
)
