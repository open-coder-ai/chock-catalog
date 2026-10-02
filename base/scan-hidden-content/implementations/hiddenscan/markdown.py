"""Markdown code blanking, line lookup, and the text-level finds: comments, definitions, KaTeX, data URIs."""

from __future__ import annotations

import bisect
import re

#: A fence opens a code block that runs to a closing fence of the same character, at least as long.
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
TICKS = re.compile(r"`+")
BLANK_LINE = re.compile(r"\n[ \t]*\n")
#: A line that opens an HTML block (CommonMark types 1-7): inside one, fences and code spans are raw HTML.
HTML_START = re.compile(r"[ \t]{0,3}<(?:[A-Za-z/!?])")
#: A link reference definition, also inside block quotes, its destination and title possibly on the next
#: line: never rendered, so its title is hidden text. Footnotes (`[^1]:`) render.
DEFINITION = re.compile(
    r"^ {0,3}(?:>[ \t]?){0,9}\[(?!\^)(?P<label>[^\]\n]{1,999})\]:[ \t]*\n?(?:[ \t]*>)?[ \t]*(?P<dest><[^>\n]*>|\S+)"
    r"(?:(?:[ \t]+|[ \t]*\n(?:[ \t]*>)?[ \t]*)(?:\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|\((?P<pq>[^)\n]*)\)))?[ \t]*$",
    re.MULTILINE,
)
IMAGE_REF = re.compile(r"!\[([^\]\n]{0,999})\](?:\[([^\]\n]{0,999})\])?(?!\()")
KATEX = re.compile(
    r"\\(?:color|textcolor|colorbox)\s*\{\s*(?:white|transparent|#?fff(?:fff)?(?:00)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*\}"
    r"|\\[hv]?phantom\s*\{",
    re.IGNORECASE,
)
DATA_HTML = re.compile(r"data:\s*text/html", re.IGNORECASE)
#: Openers of everything an HTML parser reads as a comment: <!-- -->, <!x>, <?x>, </ x>, <![CDATA[ ]]>.
OPENER = re.compile(r"<(?:!--|!\[CDATA\[|!|\?|/(?![A-Za-z]))")
ENDS = {"<!--": ("-->", "--!>"), "<![CDATA[": ("]]>",), "<!": (">",), "<?": (">",), "</": (">",)}
#: How far back a `](` looks for the `[` that opens its link text.
LOOKBACK = 1000


class Lines:
    """Offsets to 1-based line numbers, splitting on '\\n' only, as the waiver and key lookups do."""

    def __init__(self, text: str) -> None:
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)


def _spaces(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _blank_fences(lines: list[str]) -> list[str]:
    """Fenced blocks blanked; a fence inside an HTML block is raw HTML and stays."""
    out, fence, html, comment = [], None, False, False
    for line in lines:
        if fence is not None:
            closing = re.match(rf"^ {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$", line)
            fence = None if closing else fence
            out.append(_spaces(line))
            continue
        if comment or html:
            comment = comment and "-->" not in line
            html = html and bool(line.strip())
            out.append(line)
            continue
        if HTML_START.match(line):
            comment = line.lstrip().startswith("<!--") and "-->" not in line
            html = not comment
            out.append(line)
        elif opened := FENCE.match(line):
            fence = opened.group(1)
            out.append(_spaces(line))
        else:
            out.append(line)
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
    """Markdown with fenced blocks and code spans replaced by spaces, newlines kept: code is shown, not fetched."""
    fenced = "\n".join(_blank_fences(text.split("\n")))
    parts, last = [], 0
    for gap in BLANK_LINE.finditer(fenced):
        parts += [_blank_spans(fenced[last : gap.start()]), gap.group(0)]
        last = gap.end()
    parts.append(_blank_spans(fenced[last:]))
    return "".join(parts)


def tag_view(raw: str, blanked: str) -> str:
    """The raw text with only the '<' of code removed: code shows its tags and comments as text, so they
    open nothing, while the words in code stay countable inside a hidden element or comment."""
    return "".join(" " if r == "<" and b == " " else r for r, b in zip(raw, blanked, strict=True))


def comments(text: str, *, mdx: bool = False) -> list[tuple[int, str]]:
    """(offset, body) of each comment an HTML parser reads, and in MDX each `{/* */}` comment; an unclosed
    `<!--` or `{/*` runs to the end of the text."""
    if mdx:
        return _scan(text, re.compile(r"\{/\*"), {"{/*": ("*/}",)})
    return _scan(text, OPENER, ENDS)


def _scan(text: str, opener: re.Pattern[str], ends: dict[str, tuple[str, ...]]) -> list[tuple[int, str]]:
    found, done = [], 0
    # Each closer's next position is kept and searched again only once passed, so the scan stays linear.
    next_end = {closer: 0 for group in ends.values() for closer in group}
    for m in opener.finditer(text):
        if m.start() < done:
            continue
        body_start = m.end()
        if m.group(0) == "<!--" and text.startswith((">", "->"), body_start):
            done = body_start + text.startswith("->", body_start) + 1
            continue
        for closer in ends[m.group(0)]:
            if next_end[closer] != -1 and next_end[closer] < body_start:
                next_end[closer] = text.find(closer, body_start)
        found_ends = [next_end[c] for c in ends[m.group(0)] if next_end[c] != -1]
        end = min(found_ends) if found_ends else len(text)
        found.append((m.start(), text[body_start:end]))
        done = end + 1
    return found


def definitions(text: str) -> list[tuple[int, str, str, str | None]]:
    """(offset, label, destination, title) of each link reference definition, the label case-folded."""
    out = []
    for m in DEFINITION.finditer(text):
        title = next((g for g in (m.group("dq"), m.group("sq"), m.group("pq")) if g is not None), None)
        out.append((m.start(), " ".join(m.group("label").split()).casefold(), m.group("dest").strip("<>"), title))
    return out


def image_labels(text: str) -> set[str]:
    """The labels images use (`![a][label]`, `![label][]`, `![label]`): their definitions are fetched."""
    return {" ".join((m.group(2) or m.group(1)).split()).casefold() for m in IMAGE_REF.finditer(text)}


def is_image(text: str, at: int) -> bool:
    """Whether the `](` at `at` closes an image's text (`![...](`), found by bracket depth within LOOKBACK."""
    depth, i, stop = 0, at - 1, max(at - LOOKBACK, 0)
    while i >= stop:
        if text[i] == "]":
            depth += 1
        elif text[i] == "[":
            if depth == 0:
                return i > 0 and text[i - 1] == "!"
            depth -= 1
        i -= 1
    return False


def katex(text: str) -> list[int]:
    """Offsets of KaTeX white or transparent colour and phantom boxes: typeset text a reader cannot see."""
    return [m.start() for m in KATEX.finditer(text)]


def data_html(text: str) -> list[int]:
    """Offsets of `data:text/html` URIs: a whole page carried inside a link."""
    return [m.start() for m in DATA_HTML.finditer(text)]
