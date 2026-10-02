"""Read an instruction file as statements: soft-wrapped paragraphs joined and split into sentences, fenced
code taken line by line, each normalized so case, emphasis, accents and format characters do not hide a phrase."""

from __future__ import annotations

import bisect
import re
import unicodedata
from typing import NamedTuple

from instr_blocks import FENCE, Fence, nest, open_fence, table_rows

#: A statement longer than this is judged in overlapping pieces: any phrase up to OVERLAP characters long
#: lies whole inside one piece, and no rule is ever run over an unbounded string.
MAX_STATEMENT = 4000
OVERLAP = 500
#: A line that starts its own block: list item, heading, quote, table row, HTML tag, rule or front matter.
BLOCK_START = re.compile(
    r"^[ \t]*(?:[-*+](?:[ \t]|$)|[0-9]{1,9}[.)](?:[ \t]|$)|#{1,6}(?:[ \t]|$)|---+[ \t]*$|===+[ \t]*$|<(?:!--|/?(?i:address|article|aside|blockquote"
    r"|details|dialog|div|dl|fieldset|figure|footer|form|h[1-6]|header|hr|li|main|nav|ol|p|pre|section|summary|table"
    r"|tbody|td|tfoot|th|thead|tr|ul)\b))"
)
#: A front-matter line that starts a new key (not indented, not a list item).
FRONT_KEY = re.compile(r"^[^\s#-][^:]*:")
#: A blockquote prefix, also behind a list marker or a list item's indent: its lines are read as a container,
#: so a wrapped quoted paragraph is still one paragraph.
QUOTE = re.compile(r"^[ \t]{0,8}(?:(?:[-*+]|[0-9]{1,9}[.)])[ \t]+)?((?:>[ \t]?)+)")
#: A fenced line continued on the next: a trailing backslash, pipe or && (the backslash is dropped on joining).
CONTINUED = ("\\", "|", "&&")
#: Quotes or brackets around one word in prose, dropped so they cannot split a phrase (not $(x), never(x) or a
#: fake trust tag such as [inst]).
WRAPPED_WORD = re.compile(r"(?<![\w$])[\"'(\[](?!(?:inst|system|sys)[\"')\]])([\w-]+)[\"')\]]")
#: An inline <br> in prose reads as a space (a table cell's line break).
BREAK_TAG = re.compile(r"<br\s*/?>", re.IGNORECASE)
#: A markdown hard line break (two trailing spaces, a trailing backslash, <br>) ends a part of a paragraph;
#: the paragraph is also judged whole.
HARD_BREAK = ("  ", "\\")
BREAK_END = re.compile(r"<br\s*/?>$", re.IGNORECASE)
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
LINE_END = re.compile(r"\r\n|\r|\n")
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
    """The file's lines, split at LF, CRLF or a lone CR (each ends a line in CommonMark)."""
    return LINE_END.split(text)


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
    out = _front_matter(lines, front)
    out += _body(lines, front)
    return [piece for st in out for piece in _pieces(st)]


def _front_matter(lines: list[str], front: int) -> list[Statement]:
    """One statement group per front-matter key: a key's indented continuation lines and block-scalar body
    (description: > ...) belong to it."""
    out: list[Statement] = []
    parts: list[tuple[int, str]] = []
    for number, line in enumerate(lines[1 : max(front - 1, 1)], 2):
        if FRONT_KEY.match(line):
            _flush(parts, out)
        if line.strip():
            parts.append((number, line))
    _flush(parts, out)
    return out


def _body(lines: list[str], skip: int) -> list[Statement]:
    """The statements after the front matter: paragraphs, list items, table rows and headings, and fenced
    code lines (a continued line joined with the next). A blockquote is a container: its prefix is set
    aside and a statement ends only where the quote depth changes; a fence closes with its container."""
    out: list[Statement] = []
    parts: list[tuple[int, str]] = []
    whole: list[tuple[int, str]] = []  # the paragraph across hard breaks, judged whole as well
    code: list[tuple[int, str]] = []
    fence: Fence | None = None
    body: list[tuple[int, str]] = []  # the open fence's lines, also judged as prose (see _prose)
    quoted = [QUOTE.match(line) for line in lines[skip:]]
    inner = [line[m.end() :] if m else line for line, m in zip(lines[skip:], quoted, strict=True)]
    depths = [m.group(1).count(">") if m else 0 for m in quoted]
    tables = table_rows(inner)
    depth, items = 0, []  # the content indents of the open list items
    for k, line in enumerate(inner):
        number = skip + 1 + k
        if fence is not None:
            fence, taken = _step(fence, (number, line), depths[k], (code, body), out)
            if taken:
                continue
        nest(items, line, lazy=_lazy(0, whole, line))
        if depths[k] != depth and not _lazy(depths[k], parts, line):
            _end(parts, whole, out)
            depth = depths[k]
        opened = open_fence(line, depths[k], items)
        if opened or not line.strip() or BLOCK_START.match(line) or k in tables:
            _end(parts, whole, out)
            fence = opened
            if opened and opened.info:  # the info string is text a reader sees
                _flush([(number, opened.info)], out)
            if opened or not line.strip():
                continue
        parts.append((number, line))
        whole.append((number, line))
        if line.lstrip().startswith("#"):
            _end(parts, whole, out)
        elif hard_break(line):
            _flush(parts, out)
    _end(parts, whole, out)
    _flush_code(code, out)
    _prose(body, out)
    return out


def _step(
    fence: Fence, at: tuple[int, str], depth: int, held: tuple[list[tuple[int, str]], ...], out: list[Statement]
) -> tuple[Fence | None, bool]:
    """Take one line while a fence is open: the fence still open after it, and whether the line was taken
    (a body line or the closer); a line outside the fence's container ends the fence and is read as usual."""
    (number, line), (code, body) = at, held
    if fence.holds(line, depth) and (kept := _fenced(line, number, fence, code, out)):
        body.append(at)
        return kept, True
    _flush_code(code, out)
    _prose(body, out)
    return None, fence.holds(line, depth)


def _prose(body: list[tuple[int, str]], out: list[Statement]) -> None:
    """Judge a fence's lines as prose paragraphs too (a blank line or a block start begins a new one, a fence
    line stands alone), so where this reader and a markdown renderer disagree on a fence, wrapped text the
    renderer shows as prose is still joined and judged as prose."""
    group: list[tuple[int, str]] = []
    for number, line in body:
        bare = line[m.end() :] if (m := QUOTE.match(line)) else line
        if not bare.strip() or BLOCK_START.match(bare) or FENCE.match(bare):
            _flush(group, out)
        if bare.strip():
            group.append((number, bare))
        if FENCE.match(bare):
            _flush(group, out)
    _flush(group, out)
    body.clear()


def _end(parts: list[tuple[int, str]], whole: list[tuple[int, str]], out: list[Statement]) -> None:
    """End a paragraph: its last part and, where a hard break split it, the sentences that span the break,
    so a hard break cuts a negation's reach in one reading and cannot split a phrase or a command in the
    other. A sentence that crosses no break is emitted once (a second copy would count twice)."""
    breaks = [n for n, line in whole if hard_break(line)]  # line numbers, ascending
    _flush(parts, out)
    if breaks:
        out.extend(st for st in _sentences(whole) if _spans(breaks, st))
    whole.clear()


def _spans(breaks: list[int], st: Statement) -> bool:
    """True when a hard break falls inside the sentence's lines (on any line but its last)."""
    k = bisect.bisect_left(breaks, st.first)
    return k < len(breaks) and breaks[k] < st.last


def _lazy(depth: int, parts: list[tuple[int, str]], line: str) -> bool:
    """A line outside the quote that continues a quoted paragraph (CommonMark's lazy continuation)."""
    return depth == 0 and bool(parts) and bool(line.strip()) and not (FENCE.match(line) or BLOCK_START.match(line))


def hard_break(line: str) -> bool:
    """Whether `line` ends in a markdown hard break: two spaces, a backslash, or <br> (looked for near the end,
    so a long run of spaces costs one pass)."""
    return line.endswith(HARD_BREAK) or bool(BREAK_END.search(line[-64:]))


def _fenced(line: str, number: int, fence: Fence, code: list[tuple[int, str]], out: list[Statement]) -> Fence | None:
    """Take one line inside a fence; the fence that stays open, or None when this line closes it."""
    if fence.closes(line):
        _flush_code(code, out)
        return None
    if line.strip():
        code.append((number, line.strip()))
        if not line.rstrip().endswith(CONTINUED):
            _flush_code(code, out)
    return fence


def _flush_code(code: list[tuple[int, str]], out: list[Statement]) -> None:
    if code:
        joined = " ".join(text.removesuffix("\\") for _, text in code)
        out.append(Statement(code[0][0], code[-1][0], joined, normalize(joined, code=True), code=True))
        code.clear()


def _pieces(st: Statement) -> list[Statement]:
    if len(st.norm) <= MAX_STATEMENT:
        return [st]
    step = MAX_STATEMENT - OVERLAP
    return [
        st._replace(raw=st.raw[at : at + MAX_STATEMENT], norm=st.norm[at : at + MAX_STATEMENT], whole=False)
        for at in range(0, len(st.norm) - OVERLAP, step)
    ]
