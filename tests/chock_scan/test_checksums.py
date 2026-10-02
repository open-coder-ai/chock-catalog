"""chock_scan.checksums: provider-token structure and checksum validators, against cited vectors and seeded draws.

Credential-shaped inputs are drawn per run (tokens.py); scan-secrets refuses an agent-written
waiver pragma, so no credential-shaped literal is committed here.
"""

from __future__ import annotations

import string
import time
from types import ModuleType

import pytest
from chock_scan import tokens
from chock_scan.libmods import ids, load, rng, sources, stdlib_only

SOURCES = sources("checksums")
SEEDS = range(60)
GITHUB_PREFIXES = ["ghp", "gho", "ghu", "ghs", "ghr"]
#: Stripe's documented test cards (docs.stripe.com/testing): Luhn-valid, never chargeable.
STRIPE_VISA = "4242424242424242"
STRIPE_AMEX = "378282246310005"


@pytest.fixture(params=SOURCES, ids=ids(SOURCES))
def cs(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param, "checksums")


def test_base62_crc32_matches_the_published_vector(cs: ModuleType) -> None:
    # therootcompany/base62-token.js README: body zQWB...kxkJ has checksum 0mLq17. This pins the
    # alphabet order (digits, upper, lower) and that the CRC covers the 30-character body only.
    assert cs.base62_crc32("zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ") == "0mLq17"
    assert cs.base62_crc32("") == "000000"


@pytest.mark.parametrize("seed", SEEDS)
def test_crc_tokens_confirm_and_every_single_substitution_fails(cs: ModuleType, seed: int) -> None:
    r = rng(seed)
    prefix = r.choice([*GITHUB_PREFIXES, "npm"])
    token = tokens.crc_token(r, prefix)
    assert cs.base62_crc32(token[4:34]) == tokens.crc_base62(token[4:34])
    kind = "npm" if prefix == "npm" else "github"
    assert cs.check(token) == cs.Check(kind, cs.Verdict.CONFIRMED, kind)
    at = r.randrange(4, 40)
    swapped = token[:at] + r.choice(tokens.BASE62.replace(token[at], "")) + token[at + 1 :]
    assert cs.check(swapped) == cs.Check(kind, cs.Verdict.FAILED, kind)
    assert cs.check(token[:-1]).verdict is cs.Verdict.FAILED


def test_crc_tokens_with_a_bad_shape_fail(cs: ModuleType) -> None:
    for token in ["ghp_", "ghp_" + "a" * 35 + "-", "npm_" + "A" * 37, "npm_short"]:
        assert cs.check(token).verdict is cs.Verdict.FAILED, token
    # six base62 digits can exceed 32 bits; such a tail never equals a CRC32
    assert cs.check("ghp_" + "a" * 30 + "zzzzzz").verdict is cs.Verdict.FAILED


def test_longer_github_forms_are_unknown_not_failed(cs: ModuleType) -> None:
    assert cs.check("ghs_" + "A1b2_" * 20) == cs.Check("github", cs.Verdict.UNKNOWN, "github")
    assert cs.check("ghs_" + "A" * 252).verdict is cs.Verdict.FAILED


@pytest.mark.parametrize("seed", SEEDS[:20])
def test_fine_grained_pat_shape(cs: ModuleType, seed: int) -> None:
    token = tokens.github_pat(rng(seed))
    assert cs.check(token) == cs.Check("github-fine-grained", cs.Verdict.FORMAT, "github-fine-grained")
    assert cs.check(token[:-1]).verdict is cs.Verdict.FAILED
    assert cs.check(token.replace("_", "-", 2)) is cs.UNKNOWN


@pytest.mark.parametrize("seed", SEEDS[:20])
def test_slack_shapes(cs: ModuleType, seed: int) -> None:
    assert cs.check(tokens.slack(rng(seed))) == cs.Check("slack", cs.Verdict.FORMAT, "slack")


@pytest.mark.parametrize("token", ["xoxb-", "xoxb-abc-def", "xoxp-123-short", "xapp-1-", "xoxe.xoxb-x"])
def test_slack_prefix_with_a_bad_shape_fails(cs: ModuleType, token: str) -> None:
    assert cs.check(token) == cs.Check("slack", cs.Verdict.FAILED, "slack")


@pytest.mark.parametrize("seed", SEEDS[:20])
def test_stripe_shapes_name_the_key_kind(cs: ModuleType, seed: int) -> None:
    r = rng(seed)
    head = r.choice(["sk", "rk", "pk"])
    kind = {"sk": "stripe-secret", "rk": "stripe-restricted", "pk": "stripe-publishable"}[head]
    token = tokens.stripe(r, head)
    assert cs.check(token) == cs.Check(kind, cs.Verdict.FORMAT, "stripe")
    assert cs.check(token[:12]).verdict is cs.Verdict.FAILED


def test_stripe_edges(cs: ModuleType) -> None:
    assert cs.check("sk_live_" + "a" * 23).verdict is cs.Verdict.FAILED
    assert cs.check("sk_test_" + "a1" * 12 + "!").verdict is cs.Verdict.FAILED
    assert cs.check("sk_org_" + "a" * 30) is cs.UNKNOWN


@pytest.mark.parametrize("seed", SEEDS[:20])
def test_aws_access_key_id_shapes(cs: ModuleType, seed: int) -> None:
    token = tokens.aws_id(rng(seed))
    assert cs.check(token) == cs.Check("aws-access-key-id", cs.Verdict.FORMAT, "aws")
    assert cs.check(token.lower()) is cs.UNKNOWN
    assert cs.check(token[:-1]).verdict is cs.Verdict.FAILED
    assert cs.check("AIDA" + token[4:]) is cs.UNKNOWN  # an IAM user id is not a credential


@pytest.mark.parametrize("seed", SEEDS[:20])
def test_aws_secret_key_shape(cs: ModuleType, seed: int) -> None:
    secret = tokens.draw(rng(seed), tokens.BASE62 + "/+", 40)
    assert cs.aws_secret_key(secret) == cs.Check("aws-secret-access-key", cs.Verdict.FORMAT, "aws")
    assert cs.aws_secret_key(secret[:-1]).verdict is cs.Verdict.FAILED
    assert cs.aws_secret_key(secret[:-1] + "-").verdict is cs.Verdict.FAILED


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_jwts_are_well_formed(cs: ModuleType, seed: int) -> None:
    assert cs.check(tokens.jwt(rng(seed))) == cs.Check("jwt", cs.Verdict.FORMAT, "jwt")


def _jwt(header: bytes, payload: str = "e30", signature: str = "sig") -> str:
    return f"{tokens.b64url(header)}.{payload}.{signature}"


@pytest.mark.parametrize(
    "token",
    [
        _jwt(b'{"typ":"JWT"}'),  # no alg
        _jwt(b'{"alg":256}'),  # alg not a string
        _jwt(b'{"alg"'),  # not JSON
        _jwt(b'{"a\xff":"x","alg":"HS256"}'),  # not UTF-8
        _jwt(b'{"alg":"HS256"}', payload="e"),  # payload length cannot be base64url
        _jwt(b'{"alg":"HS256"}', signature="a.b"),  # four parts
        _jwt(b'{"alg":"HS256"}', payload=""),  # empty payload
        _jwt(b'{"alg":"HS256"}', signature="s!g"),  # not base64url
        _jwt(b'{"alg":"HS256"}')[:20],  # one part
        "eyJ" + "A" * (1 << 12) + ".e30.",  # header over the cap
        "eyJ",
    ],
)
def test_malformed_jwts_fail(cs: ModuleType, token: str) -> None:
    assert cs.check(token) == cs.Check("jwt", cs.Verdict.FAILED, "jwt")


def test_a_header_array_or_deep_nesting_never_escapes_as_an_exception(cs: ModuleType) -> None:
    assert cs.check(_jwt(b'["alg","HS256"]')) is cs.UNKNOWN  # not `{"`, so not claimed as a JWT
    assert cs.check(_jwt(b'{"x":[], "alg":["HS256"]}')).verdict is cs.Verdict.FAILED
    nested = b'{"alg":"HS256","x":' + b"[" * 1500 + b"]" * 1500 + b"}"
    assert len(tokens.b64url(nested)) <= cs.MAX_JWT_HEADER
    assert cs.check(_jwt(nested)).verdict in {cs.Verdict.FORMAT, cs.Verdict.FAILED}
    assert cs._has_alg(b"[" * 100_000) is False  # the recursion guard itself


@pytest.mark.parametrize(
    ("number", "verdict"),
    [
        (STRIPE_VISA, "confirmed"),
        ("4242 4242 4242 4242", "confirmed"),
        ("4242-4242-4242-4242", "confirmed"),
        (STRIPE_AMEX, "confirmed"),
        ("4242424242424241", "failed"),
        ("0000 0000 0000 0000", "failed"),  # passes Luhn; one repeated digit
        ("42424242424", "failed"),  # 11 digits
        ("42424242424242424242", "failed"),  # 20 digits
        ("4242  4242 4242 4242", "failed"),  # double space
        ("4242 4242 4242 424a", "failed"),
        (" 4242424242424242", "failed"),
        ("4" * 12 + " " * 60, "failed"),  # over MAX_CARD_TEXT
        ("", "failed"),
        ((chr(0xFF14) + chr(0xFF12)) * 8, "failed"),  # full-width digits are not ASCII digits
    ],
)
def test_luhn_cases(cs: ModuleType, number: str, verdict: str) -> None:
    assert cs.luhn(number) == cs.Check("card-number", cs.Verdict(verdict), "luhn")


@pytest.mark.parametrize("seed", SEEDS)
def test_luhn_catches_every_single_digit_error_and_adjacent_swap(cs: ModuleType, seed: int) -> None:
    r = rng(seed)
    number = tokens.card(r, r.randrange(12, 20))
    assert cs.luhn(number).verdict is cs.Verdict.CONFIRMED
    at = r.randrange(len(number))
    wrong = number[:at] + r.choice(string.digits.replace(number[at], "")) + number[at + 1 :]
    assert cs.luhn(wrong).verdict is cs.Verdict.FAILED
    pairs = [i for i in range(len(number) - 1) if number[i] != number[i + 1] and number[i : i + 2] not in {"09", "90"}]
    i = r.choice(pairs)
    assert cs.luhn(number[:i] + number[i + 1] + number[i] + number[i + 2 :]).verdict is cs.Verdict.FAILED


def test_too_long_raises_instead_of_judging(cs: ModuleType) -> None:
    assert cs.check("x" * cs.MAX_TOKEN) is cs.UNKNOWN
    with pytest.raises(cs.TokenTooLongError):
        cs.check("x" * (cs.MAX_TOKEN + 1))


FUZZ_HEADS = ["", "gh", "ghp_", "github_pat_", "npm_", "xoxb-1-", "xoxe.", "sk_live_", "pk_test_", "AKIA", "eyJ"]


@pytest.mark.parametrize("seed", range(300))
def test_arbitrary_input_gets_a_verdict_never_an_exception(cs: ModuleType, seed: int) -> None:
    r = rng(seed)
    pool = tokens.BASE62 + "_-.=+/ \t\r\n\0\ufeff\u200b\u00e9{}\"'"
    token = r.choice(FUZZ_HEADS) + tokens.draw(r, pool, r.randrange(0, 120))
    result = cs.check(token)
    assert isinstance(result.verdict, cs.Verdict)
    assert result.source in cs.SOURCES or result is cs.UNKNOWN
    assert cs.luhn(token).verdict in {cs.Verdict.CONFIRMED, cs.Verdict.FAILED}


@pytest.mark.parametrize(
    "token",
    [
        "eyJ" + "A" * 16_000 + ".e30.",
        "eyJhbGciOiJIUzI1NiJ9." + "A" * 16_000 + ".",
        "xoxb-1-" + "-" * 16_000,
        "ghp_" + "a_" * 8_000,
        "sk_live_" + "a" * 16_000,
        "AKIA" + "A" * 16_000,
    ],
)
def test_pathological_tokens_are_fast(cs: ModuleType, token: str) -> None:
    started = time.perf_counter()
    cs.check(token[: cs.MAX_TOKEN])
    cs.luhn("1 " * 32)
    assert time.perf_counter() - started < 0.5


def test_every_cited_source_is_named() -> None:
    cs = load(SOURCES[0], "checksums")
    assert set(cs.SOURCES) == {"github", "github-fine-grained", "npm", "slack", "stripe", "aws", "jwt", "luhn"}
    assert all(v.startswith(("https://", "ISO/IEC")) for v in cs.SOURCES.values())
    assert stdlib_only("checksums")
