"""The ways a renderer may read one Markdown file: (the view comments are read in, the view HTML is read in,
whether nothing holds raw text). Each extra view is read only where it differs from the text as written."""

from __future__ import annotations

import re

from hiddenscan import inline, liberal, spans
from hiddenscan.htmlspec import RAW_TEXT_ELEMENTS

#: Elements whose content this Python's HTML parser reads as raw text (the list varies by release).
RAW_TEXT = re.compile(rf"<(?:{'|'.join(RAW_TEXT_ELEMENTS)})(?![A-Za-z0-9-])", re.IGNORECASE)


def markdown(text: str, tags: str) -> list[tuple[str, str, bool]]:
    """Every reading of a Markdown file: what a renderer may read two ways is read both ways."""
    views = [
        (view, html, False)
        for view in dict.fromkeys([tags, spans.escaped_view(tags)])
        for html in dict.fromkeys([view, spans.closed_view(text, view)])
    ]
    flat = spans.flat_view(tags)
    if flat != tags or RAW_TEXT.search(tags):  # otherwise the flat reading is the first one
        views += [(tags, html, True) for html in dict.fromkeys([flat, spans.closed_view(text, flat)])]
    if (written := inline.view(text, tags)) != tags:  # paragraphs as a renderer writes them
        views += [(written, html, False) for html in dict.fromkeys([written, spans.closed_view(text, written)])]
    if (code := liberal.view(text, tags)) != tags:  # what may be code read as code, nothing swallowing
        flat = spans.flat_view(code)
        views += [(code, html, True) for html in dict.fromkeys([flat, spans.closed_view(text, flat)])]
    return views
