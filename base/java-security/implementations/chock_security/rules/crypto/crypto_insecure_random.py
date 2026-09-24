"""java.util.Random is a predictable PRNG: seeded from the clock, its output can be reconstructed."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import methods
from chock_security.pack import Rule, facts

RULE_ID = "crypto-insecure-random"

_FACTS = facts("crypto")["random"]

#: `new Random(` must not also match `new SecureRandom(`, which the plain substring would.
_PLAIN_RANDOM = re.compile(r"new\s+(?:java\.util\.)?Random\(")
_ASSIGNMENT_TARGET = re.compile(r"(\w+)\s*=")

_MESSAGE = (
    "{construct} is a predictable PRNG -- seeded from the clock and reconstructible from a few "
    "outputs -- and this value looks like a {kind}, which an attacker who predicts it can forge "
    "or replay. Use java.security.SecureRandom instead. A value that genuinely does not need to "
    f"resist prediction (a shuffle, a sample, a game) needs 'chock: allow {RULE_ID}' on this line."
)


def _construct(line: str) -> str | None:
    if _PLAIN_RANDOM.search(line):
        return "new Random()"
    return next((c for c in _FACTS["constructs"] if c != "new Random(" and c in line), None)


def _sensitive_name(*texts: str) -> str | None:
    lowered = " ".join(texts).lower()
    return next((name for name in _FACTS["sensitive_names"] if name in lowered), None)


def scan(text: FileText) -> Iterator[Finding]:
    """A weak random construct assigned to, or returned as, a token/secret/nonce/session-like value."""
    method_name_of: dict[int, str] = {}
    for method in methods(text):
        for line_no, _ in method.body:
            method_name_of[line_no] = method.name
    for line_no, line in enumerate(text.lines, 1):
        construct = _construct(line)
        if construct is None:
            continue
        target = _ASSIGNMENT_TARGET.search(line)
        context = target.group(1) if target else method_name_of.get(line_no, "")
        kind = _sensitive_name(context)
        if kind is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(construct=construct, kind=kind))


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Predictable random used for a secret value",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(generate): new Random()|Math.random()|ThreadLocalRandom.current()|"
        "RandomStringUtils.random* assigned to a token|secret|password|otp|nonce|salt|session id|"
        "api key|reset code -- use SecureRandom"
    ),
    refuses="a plain Random/Math.random/ThreadLocalRandom/RandomStringUtils value named as a token/secret/otp/nonce/salt/session id/api key/reset code",
    silent_on="the same constructs used to shuffle, sample or drive a game; any use of SecureRandom",
)
