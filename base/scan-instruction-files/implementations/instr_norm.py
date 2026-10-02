"""Statements for instr_text: the Statement record, normalization (case, accents, format characters,
emphasis), and a paragraph split into sentences."""

from __future__ import annotations

import bisect
import re
import unicodedata
from typing import NamedTuple

#: Quotes or brackets around one word in prose, dropped so they cannot split a phrase (not $(x), never(x) or a
#: fake trust tag such as [inst]).
WRAPPED_WORD = re.compile(r"(?<![\w$])[\"'(\[](?!(?:inst|system|sys)[\"')\]])([\w-]+)[\"')\]]")
#: An inline <br> in prose reads as a space (a table cell's line break).
BREAK_TAG = re.compile(r"<br\s*/?>", re.IGNORECASE)
#: A sentence ends at . ! or ? followed by space and a capital, quote, bracket or markup character.
SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'(\[<`*_~#\u00c0-\u024f])")
#: Characters folded before matching: typographic quotes and dashes become their ASCII forms.
FOLD = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u201b": "'",
        "\u2032": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": " - ",
        "\u2014": " - ",
        "\u2212": "-",
    }
)
#: Emphasis and strike marks in prose; underscores only when they are not inside a word.
EMPHASIS = re.compile(r"\*++|~~|(?<!\w)_++|(?<!_)_++(?!\w)")
SPACE = re.compile(r"\s+")
DROPPED = frozenset({"Cf", "Mn", "Me", "Cc"})


class Statement(NamedTuple):
    """One judged unit: the first and last line it spans (1-based), its raw text, its normalized text,
    and whether it came from a fenced code block (where backticks are shell syntax, not markup)."""

    first: int
    last: int
    raw: str
    norm: str
    code: bool
    #: False for a piece of a statement split for length: a rule that pairs a phrase with a target then
    #: fires on the phrase alone, since the pair may straddle two pieces.
    whole: bool = True
    #: True for the prose reading of a fence's lines (a second reading of them), which a fake trust block's
    #: span does not count.
    echo: bool = False


def normalize(text: str, *, code: bool = False) -> str:
    """Casefolded text with accents, format and control characters removed and whitespace collapsed.

    Prose also loses emphasis marks and backticks (code spans); a fenced line keeps backticks."""
    if not code:
        text = BREAK_TAG.sub(" ", text)
    if not text.isascii():
        text = "".join(map(_kept, unicodedata.normalize("NFKD", text.translate(FOLD))))
    text = text.casefold()
    if not code:
        text = WRAPPED_WORD.sub(r"\1", EMPHASIS.sub("", text.replace("`", "")))
    return SPACE.sub(" ", text).strip()


def _kept(ch: str) -> str:
    """A character as matching sees it: format, combining and control characters vanish (whitespace is a space)."""
    if unicodedata.category(ch) not in DROPPED:
        return ch
    return " " if ch.isspace() else ""


def sentences(parts: list[tuple[int, str]]) -> list[Statement]:
    """Join a paragraph's lines with spaces and split it into sentences, each keeping the lines it spans."""
    offsets, numbers, joined = [], [], ""
    for number, line in parts:
        offsets.append(len(joined))
        numbers.append(number)
        joined += line.strip() + " "
    out = []
    begin = 0
    ends = [m.start() for m in SENTENCE_END.finditer(joined)] + [len(joined)]
    for end in ends:
        # A split needs text on both sides, so no chunk is blank.
        chunk = joined[begin:end]
        first = numbers[bisect.bisect_right(offsets, begin + len(chunk) - len(chunk.lstrip())) - 1]
        last = numbers[bisect.bisect_right(offsets, end - 1) - 1]
        out.append(Statement(first, last, chunk.strip(), normalize(chunk), code=False))
        begin = end
    return out
