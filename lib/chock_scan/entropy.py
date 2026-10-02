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
#: Subresource-integrity, OCI/docker and lockfile digest spellings: an algorithm name, then the digest.
_DIGEST = re.compile(r"(?i)(?:sha(?:1|224|256|384|512)|md5|blake2b|h1)[-:=]")
#: Roadmap HP01 (1) reference forms: interpolation, templating, env lookups, encrypted-at-rest markers.
_REFERENCE = re.compile(
    r"(?i)\$\{|\$\(|\$[A-Za-z_]|\{\{|\{%|%\(|<[A-Za-z_][^>]*>|ENC\[|vault:|secretKeyRef|getenv|"
    r"os\.environ|process\.env|env\(|ENV\[|!Ref\b|!Sub\b|arn:aws:secretsmanager:"
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
        ("reference", _REFERENCE.search(value) is not None),
        ("data-uri", value[:5].lower() == "data:"),
        ("digest", _DIGEST.match(value) is not None),
        ("uuid", _UUID.fullmatch(value) is not None),
        ("placeholder", _PLACEHOLDER.search(value) is not None),
        ("sequence", any(value in run for run in _RUNS)),
    )
    for name, hit in checks:
        if hit:
            return name
    return "low-entropy" if bits < threshold else None


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
_DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc", ".txt")


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
