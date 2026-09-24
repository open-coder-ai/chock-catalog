"""Parsing a JWT with the unsigned parser reads attacker-supplied claims as if they were checked."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-jwt-unverified-parse"

_FACTS = facts("java")["jwt"]

_MESSAGE = (
    "This parses the token without checking a signature, so every claim in it is whatever the "
    "caller chose to put there. Use the signed parser -- parseClaimsJws / parseSignedClaims with "
    "a verification key -- and a real algorithm rather than none."
)

_DECODE_MESSAGE = (
    "JWT.decode() reads the claims without checking the signature, and nothing in this file "
    "verifies the token, so every claim it returns is whatever the caller typed. Verify with "
    "JWT.require(algorithm).build().verify(token). Decoding the header to choose a key before "
    "verifying is the one legitimate decode; keep that verify in this file, or put "
    f"'chock: allow {RULE_ID}' on this line."
)


def _unverified_calls(text: FileText) -> Iterator[Finding]:
    """Each call that reads a token without verifying it. The signed siblings differ by one word."""
    for line_no, line in enumerate(text.lines, 1):
        hit = next((call for call in _FACTS["unverified_calls"] if call in line), None)
        if hit is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


def _decode_never_verified(text: FileText) -> Iterator[Finding]:
    """Decode is wrong only where nothing verifies -- absence, so per file, as XStream is."""
    call = _FACTS["decode_without_verify"]
    if not text.holds(call):
        return
    if text.holds(*_FACTS["verification_calls"], *_FACTS["verified_siblings"]):
        return
    for line_no, line in enumerate(text.lines, 1):
        if call in line:
            yield Finding(RULE_ID, text.path, line_no, line, _DECODE_MESSAGE)


def scan(text: FileText) -> Iterator[Finding]:
    """The unsigned parsers and the alg-none constants, plus a decode nothing ever verifies."""
    yield from _unverified_calls(text)
    yield from _decode_never_verified(text)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="JWT read without verifying its signature",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(call): parseClaimsJwt|parseUnsecuredClaims|Algorithm.none|SignatureAlgorithm.NONE, "
        "or JWT.decode where nothing in the file verifies "
        "-- they skip the signature; use parseClaimsJws|parseSignedClaims with a key"
    ),
    refuses=(
        "`parseClaimsJwt`, `parseUnsecuredClaims`, `Algorithm.none()`, `SignatureAlgorithm.NONE`; "
        "`JWT.decode` where nothing in the file verifies"
    ),
    silent_on=(
        "`parseClaimsJws`, `parseSignedClaims`, a real algorithm, issuing a token, and a decode "
        "beside a verify"
    ),
)
