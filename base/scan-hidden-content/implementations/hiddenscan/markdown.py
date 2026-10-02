"""Line lookup and the text-level finds: comments, definitions, KaTeX, data URIs."""

from __future__ import annotations

import bisect
import re

#: A link reference definition, also inside block quotes, its destination and title possibly on the next
#: line: never rendered, so its title is hidden text. Footnotes (`[^1]:`) render.
DEFINITION = re.compile(
    r"^ {0,3}(?:>[ \t]?){0,9}\[(?!\^)(?P<label>[^\]\n]{1,999})\]:[ \t]*\n?(?:[ \t]*>)?[ \t]*(?P<dest><[^>\n]*>|\S+)"
    r"(?:(?:[ \t]+|[ \t]*\n(?:[ \t]*>)?[ \t]*)(?:\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|\((?P<pq>[^)\n]*)\)))?[ \t]*$",
    re.MULTILINE,
)
#: Labels hold no unescaped bracket, so each match stops at the next one: linear on a run of brackets.
IMAGE_REF = re.compile(r"!\[([^\[\]\n]{0,999})\](?:\[([^\[\]\n]{0,999})\])?(?!\()")
KATEX = re.compile(
    r"\\(?:color|textcolor|colorbox)\s*\{\s*(?:white|transparent|#?fff(?:fff)?(?:00)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*\}"
    r"|\\[hv]?phantom\s*\{",
    re.IGNORECASE,
)
DATA_HTML = re.compile(r"data:\s*text/html", re.IGNORECASE)
#: Openers of everything an HTML parser reads as a comment: <!-- -->, <!x>, <?x>, </ x>, <![CDATA[ ]]>.
OPENER = re.compile(r"<(?:!--|!\[CDATA\[|!|\?|/(?![A-Za-z]))")
ENDS = {"<!--": ("-->", "--!>"), "<![CDATA[": ("]]>",), "<!": (">",), "<?": (">",), "</": (">",)}


class Lines:
    """Offsets to 1-based line numbers, splitting on '\\n' only, as the waiver and key lookups do."""

    def __init__(self, text: str) -> None:
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)


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


def katex(text: str) -> list[int]:
    """Offsets of KaTeX white or transparent colour and phantom boxes: typeset text a reader cannot see."""
    return [m.start() for m in KATEX.finditer(text)]


def data_html(text: str) -> list[int]:
    """Offsets of `data:text/html` URIs: a whole page carried inside a link."""
    return [m.start() for m in DATA_HTML.finditer(text)]
