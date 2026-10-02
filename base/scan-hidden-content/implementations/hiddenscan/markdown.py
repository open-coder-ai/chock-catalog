"""Markdown code blanking, line lookup, and the text-level finds: comments, definition titles, KaTeX, data URIs."""

from __future__ import annotations

import bisect
import re

#: A fence opens a code block that runs to a closing fence of the same character, at least as long.
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
TICKS = re.compile(r"`+")
BLANK_LINE = re.compile(r"\n[ \t]*\n")
#: A paragraph that starts with a tag or comment is read as an HTML block: no code spans inside.
HTML_START = re.compile(r"[ \t]{0,3}<[A-Za-z/!?]")
#: A link reference definition: never rendered, so its title is hidden text. Footnotes (`[^1]:`) render.
DEFINITION = re.compile(
    r"^ {0,3}\[(?!\^)[^\]\n]{1,999}\]:[ \t]*(?P<dest><[^>\n]*>|\S+)"
    r"(?:[ \t]+(?:\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|\((?P<pq>[^)\n]*)\)))?[ \t]*$",
    re.MULTILINE,
)
KATEX = re.compile(
    r"\\(?:color|textcolor|colorbox)\s*\{\s*(?:white|transparent|#?fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*\}"
    r"|\\[hv]?phantom\s*\{",
    re.IGNORECASE,
)
DATA_HTML = re.compile(r"data:\s*text/html", re.IGNORECASE)


class Lines:
    """Offsets to 1-based line numbers, splitting on '\\n' only, as the waiver and key lookups do."""

    def __init__(self, text: str) -> None:
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)


def _spaces(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _blank_fences(lines: list[str]) -> list[str]:
    out, fence = [], None
    for line in lines:
        if fence is None:
            if opened := FENCE.match(line):
                fence = opened.group(1)
                out.append(_spaces(line))
                continue
            out.append(line)
            continue
        closing = re.match(rf"^ {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$", line)
        fence = None if closing else fence
        out.append(_spaces(line))
    return out


def _blank_spans(paragraph: str) -> str:
    """Code spans blanked: a backtick run opens one when a later run of the same length closes it.

    Linear: each run looks up the next run of its length once (CommonMark's rule, without escapes).
    """
    if HTML_START.match(paragraph):
        return paragraph
    runs = [(m.start(), m.end()) for m in TICKS.finditer(paragraph)]
    following: dict[int, int] = {}
    after = [-1] * len(runs)
    for i in range(len(runs) - 1, -1, -1):
        size = runs[i][1] - runs[i][0]
        after[i] = following.get(size, -1)
        following[size] = i
    chars, i = list(paragraph), 0
    while i < len(runs):
        j = after[i]
        if j < 0:
            i += 1
            continue
        start, end = runs[i][0], runs[j][1]
        chars[start:end] = _spaces(paragraph[start:end])
        i = j + 1
    return "".join(chars)


def blank_code(text: str) -> str:
    """Markdown with fenced blocks and code spans replaced by spaces, newlines kept: code is shown, not hidden."""
    fenced = "\n".join(_blank_fences(text.split("\n")))
    parts, last = [], 0
    for gap in BLANK_LINE.finditer(fenced):
        parts += [_blank_spans(fenced[last : gap.start()]), gap.group(0)]
        last = gap.end()
    parts.append(_blank_spans(fenced[last:]))
    return "".join(parts)


def comments(text: str, *, mdx: bool = False) -> list[tuple[int, str]]:
    """(offset, body) of each HTML comment, and in MDX each `{/* */}` comment; an unclosed one runs to the end."""
    found = []
    opener, closers = ("{/*", ("*/}",)) if mdx else ("<!--", ("-->", "--!>"))
    # Each closer's next position is kept and searched again only once passed, so the scan stays linear.
    next_end = dict.fromkeys(closers, 0)
    at = text.find(opener)
    while at != -1:
        body_start = at + len(opener)
        if not mdx and text.startswith((">", "->"), body_start):
            at = text.find(opener, body_start)
            continue
        for closer, pos in next_end.items():
            if pos != -1 and pos < body_start:
                next_end[closer] = text.find(closer, body_start)
        ends = [e for e in next_end.values() if e != -1]
        end = min(ends) if ends else len(text)
        found.append((at, text[body_start:end]))
        at = text.find(opener, end)
    return found


def definitions(text: str) -> list[tuple[int, str, str | None]]:
    """(offset, destination, title) of each link reference definition."""
    out = []
    for m in DEFINITION.finditer(text):
        title = next((g for g in (m.group("dq"), m.group("sq"), m.group("pq")) if g is not None), None)
        out.append((m.start(), m.group("dest").strip("<>"), title))
    return out


def katex(text: str) -> list[int]:
    """Offsets of KaTeX white or transparent colour and phantom boxes: typeset text a reader cannot see."""
    return [m.start() for m in KATEX.finditer(text)]


def data_html(text: str) -> list[int]:
    """Offsets of `data:text/html` URIs: a whole page carried inside a link."""
    return [m.start() for m in DATA_HTML.finditer(text)]
