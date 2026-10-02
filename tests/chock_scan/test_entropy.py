"""chock_scan.entropy: Shannon bits per character, charset classes, thresholds, allow reasons and path classes."""

from __future__ import annotations

import math
import string
import time
from types import ModuleType

import pytest
from chock_scan import tokens
from chock_scan.libmods import ids, load, rng, sources, stdlib_only

SOURCES = sources("entropy")
SEEDS = range(60)


@pytest.fixture(params=SOURCES, ids=ids(SOURCES))
def en(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param, "entropy")


@pytest.mark.parametrize(
    ("value", "bits"),
    [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("abcd", 2.0), ("0123456789abcdef", 4.0), ("aab", 0.9182958340544896)],
)
def test_shannon_known_values(en: ModuleType, value: str, bits: float) -> None:
    assert math.isclose(en.shannon(value), bits)


@pytest.mark.parametrize("seed", SEEDS)
def test_shannon_is_bounded_and_ignores_order_and_spelling(en: ModuleType, seed: int) -> None:
    r = rng(seed)
    value = tokens.draw(r, string.printable + "\u00e9\u4e2d", r.randrange(1, 200))
    bits = en.shannon(value)
    assert 0.0 <= bits <= math.log2(len(set(value))) + 1e-9
    shuffled = "".join(r.sample(value, len(value)))
    assert math.isclose(en.shannon(shuffled), bits)
    relabel = {c: chr(0x1000 + i) for i, c in enumerate(sorted(set(value)))}
    assert math.isclose(en.shannon("".join(relabel[c] for c in value)), bits)


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("deadBEEF0123", "hex"),
        ("abcXYZ123", "alnum"),
        ("ab+c/d==", "base64"),
        ("abc=", "base64"),
        ("ab-c_d", "base64url"),
        ("ab-c_d==", "base64url"),
        ("ab+c_d", "other"),
        ("ab=c", "other"),
        ("abc===", "other"),
        ("p@ss word", "other"),
        ("caf\u00e9", "other"),
        ("", "other"),
    ],
)
def test_charset_classes(en: ModuleType, value: str, kind: str) -> None:
    assert en.charset(value) == kind


def test_thresholds_follow_the_roadmap() -> None:
    en = load(SOURCES[0], "entropy")
    assert en.THRESHOLDS == {"hex": 3.0, "alnum": 3.5, "base64": 3.5, "base64url": 3.5, "other": 3.5}
    assert (en.MIN_LEN, en.MAX_LEN) == (16, 150)
    assert stdlib_only("entropy")


@pytest.mark.parametrize("seed", SEEDS)
def test_random_secrets_are_suspicious(en: ModuleType, seed: int) -> None:
    r = rng(seed)
    alphabet = r.choice([tokens.BASE62, tokens.BASE62 + "+/", tokens.BASE62 + "-_", string.hexdigits[:16]])
    value = tokens.draw(r, alphabet, r.randrange(32, 151))
    result = en.assess(value)
    assert result.suspicious, (value, result)
    assert result.bits >= result.threshold


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("Ab1+Ab1+Ab1+Ab1", "short"),
        ("x" * 151, "long"),
        ("${DATABASE_PASSWORD_FROM_ENV}", "reference"),
        ("$DATABASE_PASSWORD_FROM_ENV_X", "reference"),
        ("{{ secrets.DEPLOY_TOKEN_VALUE }}", "reference"),
        ("$(cat /run/secrets/token_file)", "reference"),
        ("<your-api-key-goes-right-here>", "reference"),
        ("ENC[AES256_GCM,data:Qk3vZ8pL2wXy,iv:abc]", "reference"),
        ("vault:secret/data/app#password", "reference"),
        ("os.environ['APP_SECRET_TOKEN']", "reference"),
        ("process.env.STRIPE_SECRET_KEY_V2", "reference"),
        ("!Ref DatabasePasswordParameter", "reference"),
        ("arn:aws:secretsmanager:us-east-1:123456789012:secret:x", "reference"),
        ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAE", "data-uri"),
        ("sha512-1Yjs2SvM8TflER/OD3cOjhWWOZb58A2t7wpE2S9XfBYTiIl+XFhQG2bjy4Pu1I", "digest"),
        ("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "digest"),
        ("h1:Bk3ldh4fCUyN3Zx8HuUi8cg7SsZR21qcMsS4WaxUBZw=", "digest"),
        ("123e4567-e89b-42d3-a456-426614174000", "uuid"),
        ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "placeholder"),
        ("my-sample-token-Qz8pL2wXy7Kd", "placeholder"),
        ("changeme-Qz8pL2wXy7Kd3mN", "placeholder"),
        ("xxxxxxxxQz8pL2wXy7Kd3mN", "placeholder"),
        ("Qz8pL2wXy7Kd-REDACTED-3mN", "placeholder"),
        ("0123456789012345678", "sequence"),
        ("abcdefghijklmnopqrstuvwxyz", "sequence"),
        ("ABCDEFGHIJKLMNOPQRSTUV", "sequence"),
        ("abcdefghijklmnopqrstuvwxyz0123456789", "sequence"),
        ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "sequence"),
        ("aaaaaaaaaaaaaaaaaaaaaaaa", "low-entropy"),
        ("abababababababababababab", "low-entropy"),
        ("deadbeefdeadbeefdeadbeef", "low-entropy"),
        ("correct horse battery staple", "low-entropy"),
    ],
)
def test_allow_reasons(en: ModuleType, value: str, reason: str) -> None:
    result = en.assess(value)
    assert result.reason == reason, result
    assert not result.suspicious


def test_hex_uses_the_lower_threshold(en: ModuleType) -> None:
    value = "0123456789abcdef" * 2
    hexish = "3f2a9c1e7b5d4f6a" + "0e8c2b"
    assert en.assess(hexish).charset == "hex"
    assert en.assess(hexish).threshold == 3.0
    assert en.assess(hexish).suspicious
    assert en.assess(value).charset == "hex"
    low = "0011223344556677"  # 3.0 bits exactly: at the threshold counts as high
    assert math.isclose(en.shannon(low), 3.0)
    assert en.assess(low).suspicious


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("package-lock.json", "lock"),
        ("web/yarn.lock", "lock"),
        ("Cargo.lock", "lock"),
        ("svc\\go.sum", "lock"),
        ("tests/unit/test_api.py", "fixture"),
        ("src/__tests__/client.ts", "fixture"),
        ("pkg/testdata/key.json", "fixture"),
        ("Fixtures/creds.yaml", "fixture"),
        ("docs/setup.html", "doc"),
        ("README.md", "doc"),
        ("guide/intro.rst", "doc"),
        ("src/app/config.py", None),
        ("tests", None),  # a file named tests is not inside a test directory
        ("", None),
        ("/", None),
    ],
)
def test_path_classes(en: ModuleType, path: str, kind: str | None) -> None:
    assert en.path_class(path) == kind


@pytest.mark.parametrize("seed", range(200))
def test_assess_never_raises_and_is_consistent(en: ModuleType, seed: int) -> None:
    r = rng(seed)
    value = tokens.draw(r, string.printable + "\u00e9\u200b\ufeff\0", r.randrange(0, 200))
    result = en.assess(value)
    assert result.charset in en.THRESHOLDS
    assert result.threshold == en.THRESHOLDS[result.charset]
    assert result.suspicious is (result.reason is None)
    if result.suspicious:
        assert en.MIN_LEN <= len(value) <= en.MAX_LEN
        assert result.bits >= result.threshold


@pytest.mark.parametrize(
    "value", ["<" + "a" * 148, "$" * 150, "{" * 150, "ENC[" * 37, "a" * 149 + "<", "data:" + "A" * 145]
)
def test_pathological_values_are_fast(en: ModuleType, value: str) -> None:
    started = time.perf_counter()
    for _ in range(100):
        en.assess(value)
    assert time.perf_counter() - started < 0.5
