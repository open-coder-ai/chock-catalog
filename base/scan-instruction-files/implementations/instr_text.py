"""Read an instruction file as statements: soft-wrapped paragraphs joined and split into sentences, fenced
code taken line by line, each normalized so case, emphasis, accents and format characters do not hide a phrase."""

from __future__ import annotations

import bisect
import re
import unicodedata
from typing import NamedTuple

#: A statement longer than this is judged in overlapping pieces: any phrase up to OVERLAP characters long
#: lies whole inside one piece, and no rule is ever run over an unbounded string.
MAX_STATEMENT = 4000
OVERLAP = 500
#: A fence opener: up to three spaces, then three or more backticks or tildes.
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
#: A line that starts its own block: list item, heading, quote, table row, HTML tag, rule or front matter.
BLOCK_START = re.compile(r"^\s*(?:[-*+]\s|\d{1,9}[.)]\s|#{1,6}(?:\s|$)|>|\||<[!/A-Za-z]|---+\s*$|===+\s*$)")
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
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
    }
)
#: Emphasis and strike marks in prose; underscores only when they are not inside a word.
EMPHASIS = re.compile(r"\*+|~~|(?<!\w)_+|_+(?!\w)")
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


def lines_of(text: str) -> list[str]:
    """The file's lines, split on LF only, with a trailing CR dropped (an editor's CRLF)."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def normalize(text: str, *, code: bool = False) -> str:
    """Casefolded text with accents, format and control characters removed and whitespace collapsed.

    Prose also loses emphasis marks and backticks (code spans); a fenced line keeps backticks."""
    if not text.isascii():
        text = "".join(map(_kept, unicodedata.normalize("NFKD", text.translate(FOLD))))
    text = text.casefold()
    if not code:
        text = EMPHASIS.sub("", text.replace("`", ""))
    return SPACE.sub(" ", text).strip()


def _kept(ch: str) -> str:
    """A character as matching sees it: format, combining and control characters vanish (whitespace is a space)."""
    if unicodedata.category(ch) not in DROPPED:
        return ch
    return " " if ch.isspace() else ""


def _sentences(parts: list[tuple[int, str]]) -> list[Statement]:
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


def _flush(parts: list[tuple[int, str]], out: list[Statement]) -> None:
    if not parts:
        return
    out.extend(_sentences(parts))
    parts.clear()


def _front_matter_end(lines: list[str]) -> int:
    """The line number closing a leading `---` YAML front matter block, else 0: its keys are one statement each."""
    if not lines or lines[0].strip() != "---":
        return 0
    return next((n for n, line in enumerate(lines[1:], 2) if line.strip() in ("---", "...")), 0)


def statements(text: str) -> list[Statement]:
    """Every statement in a markdown-like instruction file, in order."""
    lines = lines_of(text)
    front = _front_matter_end(lines)
    out = [
        Statement(n, n, line.strip(), normalize(line), code=False)
        for n, line in enumerate(lines[:front], 1)
        if line.strip() and n not in (1, front)
    ]
    out += _body(lines, front)
    return [piece for st in out for piece in _pieces(st)]


def _body(lines: list[str], skip: int) -> list[Statement]:
    """The statements after the front matter: paragraphs, list items and headings, and fenced code lines."""
    out: list[Statement] = []
    parts: list[tuple[int, str]] = []
    fence: str | None = None
    for number, line in enumerate(lines[skip:], skip + 1):
        if fence is not None:
            if line.strip().startswith(fence) and not line.strip().strip(fence[0]):
                fence = None
            elif line.strip():
                out.append(Statement(number, number, line.strip(), normalize(line, code=True), code=True))
            continue
        if (opener := FENCE.match(line)) or not line.strip() or BLOCK_START.match(line):
            _flush(parts, out)
            if opener:
                fence = opener.group(1)
            if opener or not line.strip():
                continue
        parts.append((number, line))
        if line.lstrip().startswith("#"):
            _flush(parts, out)
    _flush(parts, out)
    return out


def _pieces(st: Statement) -> list[Statement]:
    if len(st.norm) <= MAX_STATEMENT:
        return [st]
    step = MAX_STATEMENT - OVERLAP
    return [
        st._replace(raw=st.raw[at : at + MAX_STATEMENT], norm=st.norm[at : at + MAX_STATEMENT], whole=False)
        for at in range(0, len(st.norm) - OVERLAP, step)
    ]
