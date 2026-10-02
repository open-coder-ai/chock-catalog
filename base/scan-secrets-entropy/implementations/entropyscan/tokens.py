"""Vendor tokens whose structure checks out (chock_scan.checksums) and Luhn-valid card numbers, anywhere on a line.

Rules: `checksum` (a GitHub or npm token whose built-in CRC32 verifies), `stripe-test` (a Stripe
test-mode secret or restricted key; roadmap HP01 asks rather than blocks for these),
`vendor-format` (a Stripe live key, a Slack token or an AWS key id in the issued shape) and
`card-number` (12..19 digits with a card-network prefix whose Luhn digit holds, written in groups,
or bare on a line that names a card).

Not reported here: a GitHub or npm token whose checksum fails (scan-secrets refuses the shape), a
Stripe publishable key (meant to be public), a placeholder-looking shape (AKIA...EXAMPLE), a
published test card number, JWTs
and every vendor this module has no validator for.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

from chock_scan import checksums, entropy

#: The shapes checksums.check validates, bounded on both sides by a non-word character.
_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[0-9A-Za-z]{36}|npm_[0-9A-Za-z]{36}|(?:sk|rk)_(?:test|live)_[0-9A-Za-z]{24,247}"
    r"|(?:xoxe\.)?(?:xox[abcopres]|xapp)-[0-9]{1,32}-[0-9A-Za-z][0-9A-Za-z-]{7,250}|(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})"
    r"(?![A-Za-z0-9_])"
)
#: Card numbers in 4-4-4-1..7 or Amex 4-6-5 groups (one separator throughout), or 12..19 bare digits.
_GROUPED = re.compile(r"(?<![\w-])(?:\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -])\d{6}\2\d{5})(?![\w-])")
_BARE = re.compile(r"(?<![\w.])\d{12,19}(?![\w.])")
_CARD_WORD = re.compile(r"(?i)card|\bpan\b|cc_?num|credit")
#: Issuer prefixes of the major networks (ISO/IEC 7812 IINs): Visa 4, Mastercard 51-55 and
#: 2221-2720, Amex 34/37, Discover 6011/644-649/65, Diners 36/38/300-305, JCB 3528-3589, UnionPay 62.
_NETWORK = re.compile(
    r"4|5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)|3[47]|6(?:011|4[4-9]|5|2)|3[68]|30[0-5]|35(?:2[89]|[3-8]\d)"
)
#: Card numbers the networks and processors publish for testing (Stripe, Adyen, Braintree, PayPal
#: docs): documented dummies, like AWS's example key pair, so never a finding.
_TEST_CARDS = frozenset({
    "4242424242424242", "4000056655665556", "4111111111111111", "4012888888881881", "4222222222222",
    "5555555555554444", "5200828282828210", "5105105105105100", "2223003122003222", "378282246310005",
    "371449635398431", "378734493671000", "6011111111111117", "6011000990139424", "3056930009020004",
    "36227206271667", "3566002020360505", "6200000000000005", "4000000000000002", "4000000000009995",
})  # fmt: skip
_FORMAT_KINDS = frozenset({"stripe-secret", "stripe-restricted", "slack", "aws-access-key-id"})


class Token(NamedTuple):
    """A reported token: its 1-based line, rule, the kind checksums named (or card-number), and the text."""

    line: int
    rule: str
    kind: str
    value: str


def _token_rule(value: str) -> tuple[str, str] | None:
    """(rule, kind) for a reportable vendor token, else None."""
    result = checksums.check(value)
    if result.verdict is checksums.Verdict.CONFIRMED:
        return "checksum", result.kind
    if result.verdict is not checksums.Verdict.FORMAT or result.kind not in _FORMAT_KINDS:
        return None
    if entropy.assess(value).reason in {"placeholder", "sequence"}:
        return None
    if result.kind.startswith("stripe-") and "_test_" in value:
        return "stripe-test", result.kind
    return "vendor-format", result.kind


def _cards(line: str) -> Iterator[str]:
    """Card-shaped digit runs on a line: grouped ones always, bare ones only beside a card word."""
    yield from (m[0] for m in _GROUPED.finditer(line))
    if _CARD_WORD.search(line):
        yield from (m[0] for m in _BARE.finditer(line))


def found(lines: list[str]) -> Iterator[Token]:
    """Every reportable token and card number, line by line."""
    for number, line in enumerate(lines, 1):
        for match in _TOKEN.finditer(line):
            if rule := _token_rule(match[0]):
                yield Token(number, rule[0], rule[1], match[0])
        for text in _cards(line):
            digits = re.sub(r"[ -]", "", text)
            if digits in _TEST_CARDS or not _NETWORK.match(digits):
                continue
            if checksums.luhn(text).verdict is checksums.Verdict.CONFIRMED:
                yield Token(number, "card-number", "card-number", text)
