"""Vendor-shaped tokens drawn from a seeded generator: the property-test inputs for chock_scan.checksums.

These are random draws, built per run from a seed, so no credential-shaped literal sits in the
repository (scan-secrets refuses an agent-written waiver pragma; a person may add cited vectors).
The checksum here is an independent oracle (binascii, own base62), not the module under test.
"""

from __future__ import annotations

import base64
import binascii
import json
import random
import string

BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
UPPER_DIGITS = string.ascii_uppercase + string.digits


def draw(rng: random.Random, alphabet: str, size: int) -> str:
    """size characters drawn from alphabet."""
    return "".join(rng.choice(alphabet) for _ in range(size))


def crc_base62(text: str) -> str:
    """CRC32 of text in base62 (digits, upper, lower), zero-padded to 6."""
    value, out = binascii.crc32(text.encode()), ""
    while value:
        value, rem = divmod(value, 62)
        out = BASE62[rem] + out
    return out.rjust(6, "0")


def crc_token(rng: random.Random, prefix: str) -> str:
    """A GitHub- or npm-style token: prefix, 30 random base62 characters, their base62 CRC32."""
    body = draw(rng, BASE62, 30)
    return f"{prefix}_{body}{crc_base62(body)}"


def github_pat(rng: random.Random) -> str:
    """A fine-grained PAT shape: github_pat_, 22 base62, `_`, 59 base62."""
    return "github_pat_" + draw(rng, BASE62, 22) + "_" + draw(rng, BASE62, 59)


def slack(rng: random.Random) -> str:
    """A bot-token shape: xoxb-, numeric team and bot ids, 24 alphanumerics."""
    prefix = rng.choice(["xoxb", "xoxp", "xoxe.xoxb", "xapp", "xoxe"])
    return f"{prefix}-{draw(rng, string.digits, 11)}-{draw(rng, string.digits, 12)}-{draw(rng, BASE62, 24)}"


def stripe(rng: random.Random, head: str) -> str:
    """A Stripe key shape: head (sk/rk/pk), _test_ or _live_, 24..99 base62."""
    return f"{head}_{rng.choice(['test', 'live'])}_{draw(rng, BASE62, rng.randrange(24, 100))}"


def aws_id(rng: random.Random) -> str:
    """An AWS access key id shape: a credential prefix and 16 upper-case alphanumerics."""
    return rng.choice(["AKIA", "ASIA", "ABIA", "ACCA"]) + draw(rng, UPPER_DIGITS, 16)


def b64url(data: bytes) -> str:
    """Unpadded base64url, as JWS uses."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def jwt(rng: random.Random) -> str:
    """A JWS compact token with a random alg, claims and signature bytes."""
    header = {"alg": rng.choice(["HS256", "RS256", "ES384", "none"]), "typ": "JWT"}
    claims = {"sub": draw(rng, BASE62, rng.randrange(1, 20)), "iat": rng.randrange(1 << 31)}
    signature = rng.randbytes(rng.choice([0, 32, 64, 256]))
    return ".".join(b64url(p) for p in (json.dumps(header).encode(), json.dumps(claims).encode(), signature))


def card(rng: random.Random, length: int) -> str:
    """A Luhn-valid number of length digits, not all one digit."""
    while True:
        body = [rng.randrange(10) for _ in range(length - 1)]
        total = sum(d if i % 2 else sum(divmod(2 * d, 10)) for i, d in enumerate(reversed(body)))
        number = "".join(map(str, body)) + str(-total % 10)
        if len(set(number)) > 1:
            return number
