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
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
#: A fence indented more than this is a fence only inside a list item (else it is indented text or code).
MAX_FENCE_INDENT = 3
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d{1,9}[.)])\s")
#: A line that starts its own block: list item, heading, quote, table row, HTML tag, rule or front matter.
BLOCK_START = re.compile(
    r"^\s*(?:[-*+]\s|\d{1,9}[.)]\s|#{1,6}(?:\s|$)|---+\s*$|===+\s*$|<(?:!--|/?(?i:address|article|aside|blockquote"
    r"|details|dialog|div|dl|fieldset|figure|footer|form|h[1-6]|header|hr|li|main|nav|ol|p|pre|section|summary|table"
    r"|tbody|td|tfoot|th|thead|tr|ul)\b))"
)
#: A table's delimiter row; `|` lines start their own statements only in a run that has one (a soft-wrapped
#: line that happens to start with `|` continues its paragraph, as an autolink `<https://...>` does).
TABLE_DELIMITER = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$")
#: A front-matter line that starts a new key (not indented, not a list item).
FRONT_KEY = re.compile(r"^[^\s#-][^:]*:")
#: A blockquote prefix, also behind a list marker or a list item's indent: its lines are read as a container,
#: so a wrapped quoted paragraph is still one paragraph.
QUOTE = re.compile(r"^\s{0,8}(?:(?:[-*+]|\d{1,9}[.)])\s+)?((?:>[ \t]?)+)")
#: A fenced line continued on the next: a trailing backslash, pipe or && (the backslash is dropped on joining).
CONTINUED = ("\\", "|", "&&")
#: Quotes or brackets around one word in prose, dropped so they cannot split a phrase (not $(x), never(x) or a
#: fake trust tag such as [inst]).
WRAPPED_WORD = re.compile(r"(?<![\w$])[\"'(\[](?!(?:inst|system|sys)[\"')\]])([\w-]+)[\"')\]]")
#: An inline <br> in prose reads as a space (a table cell's line break).
BREAK_TAG = re.compile(r"<br\s*/?>", re.IGNORECASE)
#: A markdown hard line break (two trailing spaces, a trailing backslash, <br>) ends a part of a paragraph;
#: the paragraph is also judged whole.
HARD_BREAK = re.compile(r"(?: {2,}|\\|<br\s*/?>)$", re.IGNORECASE)
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


class _Fence(NamedTuple):
    """An open fence: its marker, and the quote depth and indent of its opener (a container that ends closes it)."""

    mark: str
    depth: int
    indent: int


def _opener(line: str, *, in_list: bool) -> re.Match[str] | None:
    """A fence opener: indented 4+ spaces only inside a list item, and a backtick fence's info string holding
    no backtick (else it is a code span)."""
    m = FENCE.match(line)
    if m is None or (_indent(line) > MAX_FENCE_INDENT and not in_list):
        return None
    return None if m.group(1)[0] == "`" and "`" in line.strip()[len(m.group(1)) :] else m


def _listing(line: str, *, in_list: bool) -> bool:
    """Whether a list item's content goes on after `line`: a list marker starts one, a non-blank line back at
    the margin ends it, and a blank or indented line keeps the current state."""
    if not line.strip():
        return in_list
    return bool(LIST_ITEM.match(line)) or (in_list and _indent(line) > 0)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _body(lines: list[str], skip: int) -> list[Statement]:
    """The statements after the front matter: paragraphs, list items, table rows and headings, and fenced
    code lines (a continued line joined with the next). A blockquote is a container: its prefix is set
    aside and a statement ends only where the quote depth changes; a fence closes with its container."""
    out: list[Statement] = []
    parts: list[tuple[int, str]] = []
    whole: list[tuple[int, str]] = []  # the paragraph across hard breaks, judged whole as well
    code: list[tuple[int, str]] = []
    fence: _Fence | None = None
    quoted = [QUOTE.match(line) for line in lines[skip:]]
    inner = [line[m.end() :] if m else line for line, m in zip(lines[skip:], quoted, strict=True)]
    depths = [m.group(1).count(">") if m else 0 for m in quoted]
    tables = _table_rows(inner)
    depth, in_list = 0, False
    for k, line in enumerate(inner):
        number = skip + 1 + k
        if fence is not None:
            if depths[k] >= fence.depth and not (line.strip() and _indent(line) < fence.indent):
                fence = fence if _fenced(line, number, fence.mark, code, out) else None
                continue
            _flush_code(code, out)
            fence = None
        in_list = _listing(line, in_list=in_list)
        if depths[k] != depth and not _lazy(depths[k], parts, line):
            _end(parts, whole, out)
            depth = depths[k]
        opener = _opener(line, in_list=in_list)
        if opener or not line.strip() or BLOCK_START.match(line) or k in tables:
            _end(parts, whole, out)
            if opener:
                fence = _Fence(opener.group(1), depths[k], _indent(line))
            if opener or not line.strip():
                continue
        parts.append((number, line))
        whole.append((number, line))
        if line.lstrip().startswith("#"):
            _end(parts, whole, out)
        elif HARD_BREAK.search(line):
            _flush(parts, out)
    _end(parts, whole, out)
    _flush_code(code, out)
    return out


def _end(parts: list[tuple[int, str]], whole: list[tuple[int, str]], out: list[Statement]) -> None:
    """End a paragraph: its last part and, where a hard break split it, the sentences that span the break,
    so a hard break cuts a negation's reach in one reading and cannot split a phrase or a command in the
    other. A sentence that crosses no break is emitted once (a second copy would count twice)."""
    breaks = [n for n, line in whole if HARD_BREAK.search(line)]
    _flush(parts, out)
    if breaks:
        out.extend(st for st in _sentences(whole) if any(st.first <= n < st.last for n in breaks))
    whole.clear()


def _lazy(depth: int, parts: list[tuple[int, str]], line: str) -> bool:
    """A line outside the quote that continues a quoted paragraph (CommonMark's lazy continuation)."""
    return depth == 0 and bool(parts) and bool(line.strip()) and not (FENCE.match(line) or BLOCK_START.match(line))


def _table_rows(lines: list[str]) -> set[int]:
    """Indexes of the lines in a run of `|` lines that holds a delimiter row."""
    rows: set[int] = set()
    n = 0
    while n < len(lines):
        end = n
        while end < len(lines) and lines[end].lstrip().startswith("|"):
            end += 1
        if any(TABLE_DELIMITER.match(lines[k]) for k in range(n, end)):
            rows.update(range(n, end))
        n = max(end, n + 1)
    return rows


def _fenced(line: str, number: int, fence: str, code: list[tuple[int, str]], out: list[Statement]) -> str | None:
    """Take one line inside a fence; the fence that stays open, or None when this line closes it."""
    if line.strip().startswith(fence) and not line.strip().strip(fence[0]):
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
