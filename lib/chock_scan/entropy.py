"""Shannon entropy of a candidate secret value, by charset, with the allow reasons that keep false positives low.

Thresholds are roadmap HP01 (3): values of 16..150 characters, at least 3.5 bits per character, 3.0
for hex. A verdict is a judgement on one value only; whether the value sits next to a secret-like key
is keyword_values' job, and what a finding does (block, ask) is the consuming gate's.

Limits, stated rather than hidden:
- per-character entropy cannot tell a random secret from a random non-secret of the same charset:
  a 40-hex git SHA scores like a 40-hex API key, so callers judge only keyword-adjacent values;
- a UUID is allowed (reason "uuid"), so a credential issued as a bare UUID is missed;
- a value whose text contains a placeholder word (example, changeme, ...) is allowed, so a real
  secret that happens to contain one is missed;
- a value that is wholly a reference form (`${X}`, `<...>`, `{{ x }}`, `ENC[...]`) is allowed, so a
  secret written as `<s3cr3t>` is missed; a reference form inside a longer value allows nothing;
- digests and data: URIs are allowed only with a body of the algorithm's exact length or base64;
- values longer than 150 characters are not judged here (reason "long"); blobs are NP27's.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import NamedTuple

MIN_LEN = 16
MAX_LEN = 150
#: bits per character at or above which a value is high-entropy; roadmap HP01 names 3.5 and hex 3.0.
#: alnum, base64 and base64url use the general 3.5; "other" (punctuation, spaces) does too.
THRESHOLDS = {"hex": 3.0, "alnum": 3.5, "base64": 3.5, "base64url": 3.5, "other": 3.5}

_HEX = re.compile(r"[0-9A-Fa-f]+")
_ALNUM = re.compile(r"[0-9A-Za-z]+")
_B64 = re.compile(r"[0-9A-Za-z+/]+={0,2}")
_B64URL = re.compile(r"[0-9A-Za-z_-]+={0,2}")
_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
#: Subresource-integrity, OCI/docker and lockfile digest spellings: an algorithm name, a separator,
#: then a body of exactly that algorithm's digest length in hex or (padded or not) base64/base64url.
_DIGEST = re.compile(r"(?i)(sha1|sha224|sha256|sha384|sha512|md5|blake2b|h1)[-:=](.+)")
_DIGEST_BITS = {
    "md5": 128,
    "sha1": 160,
    "sha224": 224,
    "sha256": 256,
    "h1": 256,
    "sha384": 384,
    "sha512": 512,
    "blake2b": 512,
}
_MAX_PAD = 2
_B64BODY = re.compile(r"[0-9A-Za-z+/_-]+")
_DATA_URI = re.compile(r"(?i)data:[a-z]+/[a-z0-9.+-]+(?:;[a-z0-9=._-]+)*;base64,[A-Za-z0-9+/]*={0,2}")
#: Roadmap HP01 (1) reference forms: interpolation, templating, env lookups, encrypted-at-rest markers.
#: The WHOLE value must be the reference; a reference character inside a value proves nothing
#: (generated passwords hold `$x`, `{{` and `<x>` often).
_REFERENCE = re.compile(
    r"\$\{[^{}]*\}|\$\([^()]*\)|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^{}]*\}\}|\{%[^%]*%\}|%\([A-Za-z0-9_]+\)s"
    r"|<[^<>]*>|ENC\[[^\]]*\]|vault:\S+|(?:os\.environ|process\.env|(?:os\.|System\.)?getenv\(|env\(|ENV\[)\S*"
    r"|!(?:Ref|Sub|GetAtt)\s\S+|arn:aws:secretsmanager:\S+"
)
#: Placeholder and documentation words; matched case-insensitively anywhere in the value. AWS's
#: documented dummy key pair ends in EXAMPLE and EXAMPLEKEY, so it lands here too.
_PLACEHOLDER = re.compile(
    r"(?i)example|sample|placeholder|changeme|change_me|dummy|redacted|notreal|not_a_real|your[_-]|"
    r"insert[_-]|replace[_-]?me|xxxx|\*\*\*\*|lorem|foobar|todo"
)
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_DIGITS = "0123456789"
#: Keyboard-run fillers (0123..., abcd..., the base62 alphabet in order); each is long enough to hold MAX_LEN.
_RUNS = (_DIGITS * 16, _LOWER * 6, _LOWER.upper() * 6, (_LOWER + _DIGITS) * 5, (_DIGITS + _LOWER.upper() + _LOWER) * 3)


class Assessment(NamedTuple):
    """One value's charset, entropy and verdict; `reason` names why it is allowed, None means suspicious."""

    charset: str
    bits: float
    threshold: float
    reason: str | None

    @property
    def suspicious(self) -> bool:
        """True when no allow reason applies: a high-entropy value of a judged length."""
        return self.reason is None


def shannon(value: str) -> float:
    """Shannon entropy in bits per character (0.0 for the empty string)."""
    if not value:
        return 0.0
    size = len(value)
    return -sum(n / size * math.log2(n / size) for n in Counter(value).values())


def charset(value: str) -> str:
    """The narrowest of hex, alnum, base64, base64url that spells the whole value, else "other".

    base64 needs a + or / (or padding) and base64url a - or _ to be told apart from alnum; a value
    mixing both alphabets' extra characters is "other".
    """
    if _HEX.fullmatch(value):
        return "hex"
    if _ALNUM.fullmatch(value):
        return "alnum"
    if _B64.fullmatch(value):
        return "base64"
    if _B64URL.fullmatch(value):
        return "base64url"
    return "other"


def assess(value: str) -> Assessment:
    """Judge one value; the first allow reason that applies wins, in the order the checks run.

    Reasons: short, long, reference, data-uri, digest, uuid, placeholder, sequence, low-entropy.
    """
    kind = charset(value)
    bits = shannon(value)
    threshold = THRESHOLDS[kind]
    return Assessment(kind, bits, threshold, _reason(value, bits, threshold))


def _reason(value: str, bits: float, threshold: float) -> str | None:
    """The allow reason for a value, or None."""
    if len(value) < MIN_LEN:
        return "short"
    if len(value) > MAX_LEN:
        return "long"
    checks = (
        ("reference", _REFERENCE.fullmatch(value) is not None),
        ("data-uri", _DATA_URI.fullmatch(value) is not None),
        ("digest", _is_digest(value)),
        ("uuid", _UUID.fullmatch(value) is not None),
        ("placeholder", _PLACEHOLDER.search(value) is not None),
        ("sequence", any(value in run for run in _RUNS)),
    )
    for name, hit in checks:
        if hit:
            return name
    return "low-entropy" if bits < threshold else None


def _is_digest(value: str) -> bool:
    """True for algorithm:digest where the body has exactly that algorithm's hex or base64 length."""
    match = _DIGEST.fullmatch(value)
    if match is None:
        return False
    bits, body = _DIGEST_BITS[match[1].lower()], match[2]
    if _HEX.fullmatch(body):
        return len(body) == bits // 4
    stripped = body.rstrip("=")
    return (
        _B64BODY.fullmatch(stripped) is not None
        and len(stripped) == -(-bits // 6)
        and len(body) - len(stripped) <= _MAX_PAD
    )


#: Path classes the roadmap downgrades from block to ask (HP01 FP controls). Matched on lowercased
#: path segments; the caller decides what a class means.
_LOCK_NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock",
    "pipfile.lock", "uv.lock", "pdm.lock", "cargo.lock", "go.sum", "gemfile.lock", "composer.lock",
    "packages.lock.json", "mix.lock", "pubspec.lock", "podfile.lock", "flake.lock",
})  # fmt: skip
_FIXTURE_DIRS = frozenset({
    "test", "tests", "testdata", "test-data", "spec", "specs", "__tests__", "__mocks__", "mocks",
    "fixtures", "fixture", "testing", "examples", "example", "samples",
})  # fmt: skip
_DOC_DIRS = frozenset({"docs", "doc", "documentation"})
_DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc")


def path_class(path: str) -> str | None:
    """ "lock", "fixture" or "doc" for a path the roadmap downgrades to ask, else None.

    Both separators count, so a Windows-spelled path classifies the same; the first match in that
    order wins. A downgrade is never an allow: the caller still reports, at a lower verdict.
    """
    parts = [p for p in path.replace("\\", "/").lower().split("/") if p]
    name = parts[-1] if parts else ""
    if name in _LOCK_NAMES:
        return "lock"
    if _FIXTURE_DIRS.intersection(parts[:-1]):
        return "fixture"
    if _DOC_DIRS.intersection(parts[:-1]) or name.endswith(_DOC_SUFFIXES):
        return "doc"
    return None
