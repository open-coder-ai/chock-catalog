"""Shapes a high-entropy value is written in when it is code, text or a fingerprint rather than a secret.

Each shape is a stated miss: a real secret written that way is not reported. A random credential
(base62, base64, hex) matches none of them except with negligible odds, which the tests measure.
"""

from __future__ import annotations

import re
from itertools import pairwise

#: A reference the line lexer cut at its closing bracket (`${VAR`, `$(cat f`, `{{ x`, Ruby `#{x`).
_REFERENCE_START = re.compile(r"\$?\$\(|\$\{|\{\{|\{%|%\(|#\{")
_SPACE = re.compile(r"\s")
#: A regular expression: an escaped class or metacharacter, a group construct or a character range.
_REGEX = re.compile(r"\\[sdwbSDWB.{}()\[\]|^$*+?]|\(\?[:=!<P]|\[\^?[A-Za-z0-9]-[A-Za-z0-9]")
#: A two-character escape inside a quoted value ends what the value can be (`"x\\ny"` is two lines).
_ESCAPE = re.compile(r"\\[nrt]")
_OPENERS = "{[(!*&."
#: A dotted, arrowed or scoped name, or any name followed by a call, index or type argument.
_CALL_OR_DOTTED = re.compile(
    r"[$@]?[A-Za-z_][\w$-]*(?:(?:\.|->|::|\?\.)[$@]?[A-Za-z_][\w$-]*)+(?:[(\[<].*)?|[$@]?[A-Za-z_][\w$]*[(\[<].*"
)
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_ETH = re.compile(r"0x[0-9a-fA-F]{40}")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s@]*")
#: A name or path of words: letters split on case changes, digits and / _ . : @ - separators. Each
#: word of four or more letters has a vowel in at least a fifth of its letters and no run of four
#: consonants, such words hold most of the letters, and digits are at most a quarter of the value in
#: runs of at most four. Random base62/base64 values pass about 3 in 10,000 draws, random
#: lowercase-and-digit ones about 1 in 100 (tests/policies measure both).
_WORDS = re.compile(r"(?:~|\.{1,2})?/?[A-Za-z0-9]+(?:[/_.:@-]+[A-Za-z0-9]+)*/?")
#: Words are joined by a separator or a lower-to-upper case change, never by digits alone.
_JOINED = re.compile(r"[/_.:@-]|[a-z][A-Z]")
_PARTS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_VOWEL = re.compile(r"[aeiouyAEIOUY]")
_CONSONANTS = re.compile(r"[^aeiouyAEIOUY]{4}")
_LONG = 4
_MAX_DIGITS = 4
#: The share of letters long words must hold: three quarters in a name, three fifths in a path (a
#: value with a slash and no + or =, which a random base64 value has about half the time).
_NAME_SHARE = 0.75
_PATH_SHARE = 0.6
_BASE64_ONLY = re.compile(r"[+=]")
#: The last word of a key that names something about a secret rather than the secret itself.
_KEY_TAILS = frozenset({
    "address", "addr", "url", "uri", "endpoint", "host", "hostname", "name", "names", "type", "path",
    "file", "filename", "dir", "length", "size", "expiry", "expires", "ttl", "timeout", "field",
    "header", "prefix", "pattern", "regex", "format", "label", "count", "version",
})  # fmt: skip
_KEY_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
#: A key naming a file (`app.py`, `index.json`) whose value is a hex digest: a checksum manifest row.
_FILE_KEY = re.compile(
    r"(?i).+\.(?:py|js|mjs|cjs|ts|json|ya?ml|toml|sh|md|txt|lock|cfg|ini|html|css|jar|whl|tgz|gz|zip)"
)
_HEX_DIGEST = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}")
_RUN = 4
MIN_LEN = 16


def trim(value: str) -> str:
    """The value up to its first escaped newline or tab; the rest is another line of a string literal."""
    return _ESCAPE.split(value, maxsplit=1)[0]


def explain(value: str, key: str) -> str | None:
    """The name of the non-secret shape the value is written in, or None when it could be a secret."""
    bare = value.lstrip(_OPENERS)
    checks = (
        ("reference", _REFERENCE_START.match(value)),
        ("text", _SPACE.search(value)),
        ("regex", _REGEX.search(value)),
        ("filler", len(value) - _run_chars(value) < MIN_LEN),
        ("code-name", not bare.startswith("eyJ") and _CALL_OR_DOTTED.fullmatch(bare)),
        ("variable-name", _ENV_NAME.fullmatch(value)),
        ("url", _URL.fullmatch(value)),
        ("words", _WORDS.fullmatch(value) and _JOINED.search(value) and _wordy(value)),
        ("eth-address", _ETH.fullmatch(value)),
        ("non-ascii", not value.isascii()),
        ("file-digest", _FILE_KEY.fullmatch(key) and _HEX_DIGEST.fullmatch(value)),
        ("key-names-no-secret", _key_tail(key) in _KEY_TAILS),
    )
    return next((name for name, hit in checks if hit), None)


def _wordy(value: str) -> bool:
    """True when value reads as words (see _WORDS); random credentials almost never do."""
    parts = _PARTS.findall(value)
    words = [p for p in parts if not p.isdigit()]
    digits = [p for p in parts if p.isdigit()]
    if len(parts) < 2 or not words or 4 * sum(map(len, digits)) > len(value):  # noqa: PLR2004 -- a quarter
        return False
    if any(len(d) > _MAX_DIGITS for d in digits):
        return False
    long_words = [w for w in words if len(w) >= _LONG]
    if not all(5 * len(_VOWEL.findall(w)) >= len(w) and not _CONSONANTS.search(w) for w in long_words):
        return False
    share = _PATH_SHARE if "/" in value and not _BASE64_ONLY.search(value) else _NAME_SHARE
    return sum(map(len, long_words)) >= share * sum(map(len, words))


def _key_tail(key: str) -> str:
    """The key's last word, lower-cased; a secret-like key always has one."""
    return _KEY_WORDS.findall(key)[-1].lower()


def _run_chars(value: str) -> int:
    """Characters inside ascending runs of _RUN or more (abcd, 1234): keyboard filler, not randomness."""
    total, length = 0, 1
    for prev, char in pairwise(value):
        if ord(char) == ord(prev) + 1 and char.isalnum() and prev.isalnum():
            length += 1
            continue
        total += length if length >= _RUN else 0
        length = 1
    return total + (length if length >= _RUN else 0)
