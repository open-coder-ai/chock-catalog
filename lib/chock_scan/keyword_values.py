"""Values assigned to secret-like keys, line by line: the candidates the entropy tier judges (roadmap HP01 (3)).

Forms: `key = v`, `key: v`, `"key": "v"`, `key => v`, `key := v`, `KEY=v`, each optionally quoted on
either side. A key is secret-like when one of its words (split on case changes, digits and
separators) is a secret noun, or two adjacent words are a key bigram (api key, client secret, ...).

Limits, stated rather than hidden:
- one line at a time: a key and value split across lines (YAML block scalars, continuation lines)
  are missed;
- a quoted value (one to three quote characters, so Python and TOML triple quotes count) ends at the
  next quote character of any kind, a bare one at whitespace or `,;&#)}]`; an escaped quote or a `#`
  ends a value early, and the prefix is judged only if it is still MIN_LEN long;
- only space and tab count as blanks, at most 16 either side of the operator (a no-break space or a
  wider gap is missed); XML forms (`<password>v</password>`, `key="password" value="v"`) are missed;
- every offset is tried, so a key inside another assignment's value (`url=https://h/?token=...`)
  is still found, and a value is reported once, under the first key that names it;
- keys are ASCII words; a key longer than 128 characters is seen only from a dash or dot inside its
  last 128;
- only values of MIN_LEN..MAX_LEN (16..150, entropy's judged range) characters are yielded;
- input above MAX_CHARS raises TooLargeError instead of being judged in part.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from itertools import pairwise
from typing import NamedTuple

MAX_CHARS = 1 << 20
MIN_LEN = 16
MAX_LEN = 150

#: A key starts only where no word character precedes it, so a long word is tried once, not at
#: every offset; a key is at most 128 characters, at most 16 blanks sit either side of the operator
#: and a value is read to at most MAX_LEN + 1 characters (enough to tell it is too long), so each offset costs a bounded amount (no nested
#: quantifier can backtrack; every quantifier is possessive, so no offset re-scans its own key).
#: Keys may hold dots and dashes (`spring.datasource.password`, `api-key`). A YAML tag or anchor
#: (`!!str`, `&a`) and an auth scheme word (`Bearer`, `Basic`, `Token`, `Bot`) before the value are skipped.
_ASSIGN = re.compile(
    r"""(?<![A-Za-z0-9_])(?P<kq>["'`]?)(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,127}+)(?P=kq)[ \t]{0,16}+(?::=|=>|[:=])"""
    r"""[ \t]{0,16}+(?:(?:!{1,2}[\w./:-]{0,64}+|&[\w.-]{1,64}+)[ \t]{1,16}+){0,2}+"""
    r"""(?:(?i:bearer|basic|token|bot)[ \t]{1,16}+)?+"""
    r"""(?:(?P<q>["'`]{1,3}+)(?P<qval>[^"'`\r\n]{0,151}+)|(?P<val>[^\s"'`,;&#)}\]]{1,151}+))"""
)
_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_NOUNS = frozenset({
    "password", "passwords", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "tokens",
    "credential", "credentials", "apikey", "apikeys", "bearer", "auth", "authorization", "dsn", "privatekey",
})  # fmt: skip
_KEY_HEADS = frozenset({
    "api", "access", "secret", "private", "signing", "encryption", "master", "client", "app",
    "session", "account", "storage", "license", "webhook", "service",
})  # fmt: skip


class TooLargeError(ValueError):
    """The text is larger than MAX_CHARS; the caller refuses or reports, it never treats it as clean."""


class Candidate(NamedTuple):
    """A secret-like key and its value; `line` is 1-based, `column` 0-based (of the value)."""

    line: int
    column: int
    key: str
    value: str


def secret_key(name: str) -> bool:
    """True when the key name has a secret noun, or a head word followed by key/secret/token."""
    words = [w.lower() for w in _WORDS.findall(name)]
    if _NOUNS.intersection(words):
        return True
    return any(a in _KEY_HEADS and b in {"key", "keys"} for a, b in pairwise(words))


def candidates(text: str) -> Iterator[Candidate]:
    """Each value of MIN_LEN..MAX_LEN characters assigned to a secret-like key, in text order.

    Lines split on \\n, \\r\\n and \\r alike, so a CRLF or CR file reports the same values.
    """
    if len(text) > MAX_CHARS:
        msg = f"text of {len(text)} characters is larger than {MAX_CHARS}"
        raise TooLargeError(msg)
    for number, line in enumerate(re.split(r"\r\n|\r|\n", text), 1):
        pos = 0
        seen: set[int] = set()
        while match := _ASSIGN.search(line, pos):
            pos = match.start() + 1
            group = "qval" if match["q"] else "val"
            value, column = match[group], match.start(group)
            if column not in seen and MIN_LEN <= len(value) <= MAX_LEN and secret_key(match["key"]):
                seen.add(column)
                yield Candidate(number, column, match["key"], value)
