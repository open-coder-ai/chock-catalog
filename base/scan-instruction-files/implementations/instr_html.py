"""CommonMark HTML blocks (types 1-7), tracked only to tell when this reader and any markdown renderer must
agree that a fence line opens a fence: a fence line inside an HTML block is raw HTML to a renderer."""

from __future__ import annotations

import re

#: An HTML block start (up to three spaces of indent) and the end condition of each type: a pattern that
#: ends it on the line where it matches, or BLANK (it ends before the next blank line).
BLANK = "blank"
_RAW = "pre|script|style|textarea"
_TAGS = (
    "address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div"
    "|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li"
    "|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td"
    "|tfoot|th|thead|title|tr|track|ul"
)
STARTS: tuple[tuple[re.Pattern[str], re.Pattern[str] | str], ...] = (
    (re.compile(rf"[ \t]{{0,3}}<(?:{_RAW})(?:[ \t>]|$)", re.IGNORECASE), re.compile(rf"</(?:{_RAW})>", re.IGNORECASE)),
    (re.compile(r"[ \t]{0,3}<!--"), re.compile(r"-->")),
    (re.compile(r"[ \t]{0,3}<\?"), re.compile(r"\?>")),
    (re.compile(r"[ \t]{0,3}<![A-Za-z]"), re.compile(r">")),
    (re.compile(r"[ \t]{0,3}<!\[CDATA\["), re.compile(r"\]\]>")),
    (re.compile(rf"[ \t]{{0,3}}</?(?:{_TAGS})(?:[ \t]|/?>|$)", re.IGNORECASE), BLANK),
    # Type 7, any complete tag alone on its line (it cannot interrupt a paragraph; counted anyway, which
    # only makes fewer fences sure).
    (re.compile(r"[ \t]{0,3}</?[A-Za-z][\w-]*+[^<>]*+>[ \t]*$"), BLANK),
)


def html_step(state: re.Pattern[str] | str | None, line: str) -> re.Pattern[str] | str | None:
    """The HTML block state after `line` (the end condition of the open block, or None when none is open)."""
    if state is None:
        start = next((end for begin, end in STARTS if begin.match(line)), None)
        if start is None:
            return None
        state = start  # the start line itself may hold the end marker (<!-- --> on one line)
    if state == BLANK:
        return None if not line.strip() else BLANK
    return None if state.search(line) else state
