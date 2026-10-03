"""Structural validators that tell a real-shaped provider token from a fake one, offline, with each source cited.

check(token) picks the validator by prefix and returns a Check: CONFIRMED (a checksum built into
the format verifies), FORMAT (the expected shape matches; the format carries no checksum), FAILED
(a checksum or a published structure does not hold: the GitHub and npm CRC32 on their 40-character
form, JWT structure, Luhn) or UNKNOWN (no validator applies, or the token is not the shape a check
is defined on, since vendors publish prefixes, not lengths). luhn() and aws_secret_key() are called directly: neither
shape has a prefix to dispatch on.

What a verdict is not: CONFIRMED says the token could have been issued, never that it is live
(that needs the network, which a gate never uses). FAILED is never proof of harmlessness: a
consumer may lower its verdict on FAILED, never drop the finding. A token longer than MAX_TOKEN
raises TokenTooLongError instead of a verdict.
"""

from __future__ import annotations

import base64
import binascii
import enum
import json
import re
import zlib
from typing import NamedTuple

MAX_TOKEN = 1 << 14
MAX_JWT_HEADER = 1 << 12
#: ISO/IEC 7812-1 PAN lengths judged; MAX_CARD_TEXT bounds the spaced or dashed spelling.
CARD_DIGITS = range(12, 20)
MAX_CARD_TEXT = 64
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

SOURCES = {
    "github": "https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/",
    "github-fine-grained": "https://github.blog/security/application-security/introducing-fine-grained-personal-access-tokens-for-github/",
    "npm": "https://github.blog/changelog/2021-09-23-npm-has-a-new-access-token-format/",
    "slack": "https://docs.slack.dev/authentication/tokens",
    "stripe": "https://docs.stripe.com/keys",
    "aws": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids",
    "jwt": "https://www.rfc-editor.org/rfc/rfc7519 (sections 3, 6.1, 7.2); RFC 7515 7.1; RFC 7516 7.1; RFC 4648 5",
    "luhn": "ISO/IEC 7812-1:2017 Annex B (Luhn formula for computing modulus-10 double-add-double check digits)",
}  # fmt: skip


class Verdict(enum.Enum):
    """How far a token's structure was confirmed."""

    CONFIRMED = "confirmed"
    FORMAT = "format"
    FAILED = "failed"
    UNKNOWN = "unknown"


class Check(NamedTuple):
    """A verdict and the token kind it was reached for ("" when UNKNOWN); SOURCES[source] cites the rule."""

    kind: str
    verdict: Verdict
    source: str


class TokenTooLongError(ValueError):
    """The token is longer than MAX_TOKEN; the caller reports it rather than treating it as unvalidated."""


UNKNOWN = Check("", Verdict.UNKNOWN, "")

#: GitHub (blog above): a gh + type letter prefix and `_`, 30 base62 characters, then a CRC32 of
#: those 30 encoded in base62, left-padded with zeros to 6. Which bytes the CRC covers (the 30, not
#: the prefix) and the alphabet order (digits, upper, lower) are not in the blog: they come from a
#: third-party implementation (therootcompany/base62-token.js), whose published vector the tests pin.
_GITHUB = re.compile(r"(gh[pousr])_([0-9A-Za-z]{30})([0-9A-Za-z]{6})")
#: Fine-grained PATs: the prefix is documented; the 22 + `_` + 59 layout is observed, not published,
#: so another layout is UNKNOWN.
_GITHUB_PAT = re.compile(r"github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}")
_NPM = re.compile(r"(npm)_([0-9A-Za-z]{30})([0-9A-Za-z]{6})")
#: Slack (docs above): bot xoxb-, user xoxp-, refresh xoxe-, rotating xoxe.xoxb-/xoxe.xoxp-,
#: app-level xapp-, legacy workspace xoxa-/xoxr-, and the xoxc-/xoxs-/xoxo- forms seen in use. The
#: docs publish prefixes, not lengths: FORMAT is a numeric first segment then at least one more of
#: at least 8 characters; anything else under a Slack prefix is UNKNOWN.
_SLACK = re.compile(r"(?:xoxe\.)?(?:xox[abcopres]|xapp)-[0-9]+-[0-9A-Za-z][0-9A-Za-z-]{7,}")
_SLACK_PREFIX = re.compile(r"(?:xoxe\.)?(?:xox[abcopres]|xapp)-")
#: Stripe (docs above): sk_ secret, rk_ restricted, pk_ publishable (safe to expose), each _test_ or
#: _live_. Lengths are not published: FORMAT needs 24 or more base62 characters (a floor chosen
#: here, not a vendor rule); anything else under a Stripe prefix is UNKNOWN.
_STRIPE = re.compile(r"(sk|rk|pk)_(test|live)_[0-9A-Za-z]{24,247}")
_STRIPE_PREFIX = re.compile(r"(sk|rk|pk)_(test|live)_")
_STRIPE_KIND = {"sk": "stripe-secret", "rk": "stripe-restricted", "pk": "stripe-publishable"}
#: AWS (IAM identifiers above): the credential prefixes AKIA (access key), ASIA (temporary access
#: key), ABIA (STS bearer token), ACCA (context-specific credential). FORMAT is the 20-character
#: upper-case alphanumeric ID AWS issues today (the IAM API allows 16..128), else UNKNOWN.
_AWS_ID = re.compile(r"(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}")
_AWS_PREFIX = re.compile(r"AKIA|ASIA|ABIA|ACCA")
_AWS_SECRET = re.compile(r"[0-9A-Za-z/+]{40}")
_JWT = re.compile(r"([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)")
_JWE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_CARD = re.compile(r"[0-9]+(?:[ -][0-9]+)*")
#: A doubled digit with its two digits added: 0 2 4 6 8 1 3 5 7 9.
_DOUBLED = tuple(sum(divmod(2 * d, 10)) for d in range(10))


def base62_crc32(text: str) -> str:
    """The CRC32 of text's bytes in BASE62, zero-padded to 6 characters (GitHub's and npm's checksum)."""
    value = zlib.crc32(text.encode("ascii"))
    digits = ""
    while value:
        value, rem = divmod(value, 62)
        digits = BASE62[rem] + digits
    return digits.rjust(6, "0")


def check(token: str) -> Check:
    """The verdict for a token, picked by its prefix; UNKNOWN when no validator's prefix matches."""
    if len(token) > MAX_TOKEN:
        msg = f"token of {len(token)} characters is longer than {MAX_TOKEN}"
        raise TokenTooLongError(msg)
    for validator in (_github, _npm, _slack, _stripe, _aws_id, _jwt):
        result = validator(token)
        if result is not None:
            return result
    return UNKNOWN


def _shape(token: str, pattern: re.Pattern[str], kind: str, source: str) -> Check:
    """FORMAT when the expected shape matches, else UNKNOWN: a shape-only check never says FAILED."""
    return Check(kind, Verdict.FORMAT if pattern.fullmatch(token) else Verdict.UNKNOWN, source)


def _crc_token(token: str, pattern: re.Pattern[str], kind: str, source: str) -> Check:
    """CONFIRMED when the 6-character tail is the base62 CRC32 of the 30 before it, FAILED when it is
    not; UNKNOWN when the token is not the 40-character shape the checksum is defined on."""
    match = pattern.fullmatch(token)
    if match is None:
        return Check(kind, Verdict.UNKNOWN, source)
    ok = base62_crc32(match[2]) == match[3]
    return Check(kind, Verdict.CONFIRMED if ok else Verdict.FAILED, source)


def _github(token: str) -> Check | None:
    if token.startswith("github_pat_"):
        return _shape(token, _GITHUB_PAT, "github-fine-grained", "github-fine-grained")
    if not re.match(r"gh[pousr]_", token):
        return None
    return _crc_token(token, _GITHUB, "github", "github")


def _npm(token: str) -> Check | None:
    return _crc_token(token, _NPM, "npm", "npm") if token.startswith("npm_") else None


def _slack(token: str) -> Check | None:
    if not _SLACK_PREFIX.match(token):
        return None
    return _shape(token, _SLACK, "slack", "slack")


def _stripe(token: str) -> Check | None:
    prefix = _STRIPE_PREFIX.match(token)
    if prefix is None:
        return None
    return _shape(token, _STRIPE, _STRIPE_KIND[prefix[1]], "stripe")


def _aws_id(token: str) -> Check | None:
    if not _AWS_PREFIX.match(token):
        return None
    return _shape(token, _AWS_ID, "aws-access-key-id", "aws")


def aws_secret_key(token: str) -> Check:
    """FORMAT for the 40-character base64-alphabet shape of an AWS secret access key, else UNKNOWN."""
    return _shape(token, _AWS_SECRET, "aws-secret-access-key", "aws")


def _jwt(token: str) -> Check | None:
    """A JWS compact JWT (RFC 7515 7.1): three base64url parts, the header a JSON object with a string alg.

    Only tokens starting `eyJ` (base64url of `{"`) are claimed; the signature part may be empty (an
    unsecured JWT, RFC 7519 6.1). The payload must decode as base64url; its JSON is not required
    (a JWS payload need not be JSON). The signature is never verified. A five-part token is a JWE
    (RFC 7516 7.1), which this does not validate: UNKNOWN.
    """
    if not token.startswith("eyJ"):
        return None
    if _JWE.fullmatch(token):
        return Check("jwt", Verdict.UNKNOWN, "jwt")
    match = _JWT.fullmatch(token)
    header = _b64url(match[1]) if match and len(match[1]) <= MAX_JWT_HEADER else None
    ok = header is not None and _b64url(match[2]) is not None and _has_alg(header)
    return Check("jwt", Verdict.FORMAT if ok else Verdict.FAILED, "jwt")


def _b64url(part: str) -> bytes | None:
    """Unpadded base64url decoded (RFC 7515 2), or None when the length or bits cannot be base64url."""
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError):
        return None


def _has_alg(header: bytes) -> bool:
    """True when header is UTF-8 JSON holding an object with a string "alg"."""
    try:
        data = json.loads(header.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False
    return isinstance(data, dict) and isinstance(data.get("alg"), str)


def luhn(number: str) -> Check:
    """CONFIRMED for a 12..19-digit number whose Luhn check digit holds (ISO/IEC 7812-1), else FAILED.

    Single spaces or dashes between digit groups are allowed; text longer than MAX_CARD_TEXT is FAILED
    unread, and so is one repeated digit (0000 0000 0000 0000 passes Luhn but is a placeholder).
    """
    spelled = len(number) <= MAX_CARD_TEXT and _CARD.fullmatch(number) is not None
    digits = number.replace(" ", "").replace("-", "") if spelled else ""
    ok = len(digits) in CARD_DIGITS and len(set(digits)) > 1 and _luhn_sum(digits) % 10 == 0
    return Check("card-number", Verdict.CONFIRMED if ok else Verdict.FAILED, "luhn")


def _luhn_sum(digits: str) -> int:
    """The Luhn sum: from the right, every second digit doubled with its digits added."""
    return sum(int(char) if index % 2 == 0 else _DOUBLED[int(char)] for index, char in enumerate(reversed(digits)))
