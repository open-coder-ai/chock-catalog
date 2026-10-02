"""Read an instruction file as statements: soft-wrapped paragraphs joined and split into sentences, fenced
code taken line by line, each normalized so case, emphasis, accents and format characters do not hide a phrase."""

from __future__ import annotations

import bisect
import re
from typing import Any

from instr_blocks import FENCE, Fence, nest, open_fence, table_rows
from instr_html import html_step
from instr_norm import Statement, normalize, sentences

#: A statement longer than this is judged in overlapping pieces: any phrase up to OVERLAP characters long
#: lies whole inside one piece, and no rule is ever run over an unbounded string.
MAX_STATEMENT = 4000
OVERLAP = 500
#: A line that starts its own block: list item, heading, quote, table row, HTML tag, thematic break or rule.
BLOCK_START = re.compile(
    r"^(?:[ \t]{0,3}#{1,6}(?:[ \t]|$)|[ \t]*(?:[-*+](?:[ \t]|$)|[0-9]{1,9}[.)](?:[ \t]|$)|---+[ \t]*$|===+[ \t]*$|(?:\*[ \t]*+){3,}+$|(?:_[ \t]*+){3,}+$|<(?:!--|/?(?i:address|article|aside|blockquote"
    r"|details|dialog|div|dl|fieldset|figure|footer|form|h[1-6]|header|hr|li|main|nav|ol|p|pre|section|summary|table"
    r"|tbody|td|tfoot|th|thead|tr|ul)\b)))"
)
#: A front-matter line that starts a new key: a plain YAML key at the margin, then a colon and a space or the end.
FRONT_KEY = re.compile(r"^[A-Za-z0-9_][\w.-]*+:(?:[ \t]|$)")
#: A blockquote prefix, also behind a list marker or a list item's indent: its lines are read as a container,
#: so a wrapped quoted paragraph is still one paragraph.
QUOTE = re.compile(r"^[ \t]{0,8}(?:(?:[-*+]|[0-9]{1,9}[.)])[ \t]+)?((?:>[ \t]?)+)")
#: A fenced line continued on the next: a trailing backslash, pipe or && (the backslash is dropped on joining).
CONTINUED = ("\\", "|", "&&")
#: A markdown hard line break (two trailing spaces, a trailing backslash, <br>) ends a part of a paragraph;
#: the paragraph is also judged whole.
HARD_BREAK = ("  ", "\\")
BREAK_END = re.compile(r"<br\s*/?>$", re.IGNORECASE)
#: An ATX heading: one line, its own block.
HEADING = re.compile(r"[ \t]{0,3}#{1,6}(?:[ \t]|$)")
LINE_END = re.compile(r"\r\n|\r|\n")


def lines_of(text: str) -> list[str]:
    """The file's lines, split at LF, CRLF or a lone CR (each ends a line in CommonMark)."""
    return LINE_END.split(text)


def _flush(parts: list[tuple[int, str]], out: list[Statement]) -> None:
    if not parts:
        return
    out.extend(sentences(parts))
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
    (description: > ...) belong to it. With more than one key the block is also judged whole, so a line that
    looks like a key cannot cut a wrapped sentence in two."""
    out: list[Statement] = []
    parts: list[tuple[int, str]] = []
    every = [(number, line) for number, line in enumerate(lines[1 : max(front - 1, 1)], 2) if line.strip()]
    for number, line in every:
        if FRONT_KEY.match(line):
            _flush(parts, out)
        parts.append((number, line))
    keys = len(out)
    _flush(parts, out)
    if keys:
        _flush(every, out)
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
    html = None  # the end condition of an open HTML block
    for k, line in enumerate(inner):
        number = skip + 1 + k
        tail: list[tuple[int, str]] = []
        if fence is not None:
            fence, taken, tail = _step(fence, (number, line), depths[k], (code, body), out)
            if taken:
                continue
        nest(items, line, lazy=_lazy(0, whole, line))  # a line that ends a fence's container is not lazy
        parts += tail  # the fence's last paragraph, which that line may continue (a renderer saw no fence)
        whole += tail
        if depths[k] != depth and not _lazy(depths[k], parts, line):
            _end(parts, whole, out)
            depth = depths[k]
        opened, html = _opening(line, depths[k], items, html)
        if opened or not line.strip() or BLOCK_START.match(line) or k in tables:
            _end(parts, whole, out)
            fence = opened
            if opened and opened.info:  # the info string is text a reader sees
                _flush([(number, opened.info)], out)
            if opened or not line.strip():
                continue
        parts.append((number, line))
        whole.append((number, line))
        if HEADING.match(line):
            _end(parts, whole, out)
        elif hard_break(line):
            _flush(parts, out)
    _end(parts, whole, out)
    _flush_code(code, out)
    _prose(body, out, carry=False)
    return out


def _opening(line: str, depth: int, items: list[int], html: re.Pattern[str] | str | None) -> tuple[Fence | None, Any]:
    """The fence `line` opens, if any, and the HTML block state after it. A fence is sure when every renderer
    reads it as one: opened at the margin, outside any list, quote or HTML block."""
    opened = open_fence(line, depth, items)
    if opened is None:
        return None, html_step(html, line)
    return opened._replace(sure=html is None and depth == 0 and not items and not line[:1].isspace()), html


def _step(
    fence: Fence, at: tuple[int, str], depth: int, held: tuple[list[tuple[int, str]], ...], out: list[Statement]
) -> tuple[Fence | None, bool, list[tuple[int, str]]]:
    """Take one line while a fence is open: the fence still open after it, whether the line was taken (a body
    line or the closer), and when a line outside the fence's container ends it, the body's last paragraph:
    a renderer that saw no fence there joins it with that line."""
    (number, line), (code, body) = at, held
    if fence.holds(line, depth) and _fenced(line, number, code, out, closer=fence.closes(line, depth)):
        body.append(at)
        return fence, True, []
    _flush_code(code, out)
    taken = fence.holds(line, depth)  # here, only the fence's closer is taken
    return None, taken, _prose(body, out, carry=not taken, capped=taken and fence.sure)


def _prose(
    body: list[tuple[int, str]], out: list[Statement], *, carry: bool, capped: bool = False
) -> list[tuple[int, str]]:
    """Judge a fence's lines as prose paragraphs too, so where this reader and a markdown renderer disagree on
    a fence, wrapped text the renderer shows as prose is still joined and judged as prose: a blank line or a
    block start begins a paragraph, a fence line or a heading stands alone. With `carry`, the last paragraph
    is returned to be continued instead of judged here; `capped` marks the reading of a sure, closed fence."""
    group: list[tuple[int, str]] = []
    read: list[Statement] = []
    for number, line in body:
        bare = line[m.end() :] if (m := QUOTE.match(line)) else line
        if not bare.strip() or BLOCK_START.match(bare) or FENCE.match(bare):
            _flush(group, read)
        if bare.strip():
            group.append((number, bare))
        if FENCE.match(bare) or HEADING.match(bare):
            _flush(group, read)
    last = group[:] if carry else []
    if not carry:
        _flush(group, read)
    out.extend(st._replace(echo=True, capped=capped) for st in read)
    body.clear()
    return last


def _end(parts: list[tuple[int, str]], whole: list[tuple[int, str]], out: list[Statement]) -> None:
    """End a paragraph: its last part and, where a hard break split it, the sentences that span the break,
    so a hard break cuts a negation's reach in one reading and cannot split a phrase or a command in the
    other. A sentence that crosses no break is emitted once (a second copy would count twice)."""
    breaks = [n for n, line in whole if hard_break(line)]  # line numbers, ascending
    _flush(parts, out)
    if breaks:
        out.extend(st for st in sentences(whole) if _spans(breaks, st))
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


def _fenced(line: str, number: int, code: list[tuple[int, str]], out: list[Statement], *, closer: bool) -> bool:
    """Take one line inside a fence; whether the fence stays open (False when this line is its closer)."""
    if closer:
        _flush_code(code, out)
        return False
    if line.strip():
        code.append((number, line.strip()))
        if not line.rstrip().endswith(CONTINUED):
            _flush_code(code, out)
    return True


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
