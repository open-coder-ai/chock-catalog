"""scan-hidden-content: inputs shaped to make a reader quadratic stay within the gate's 30-second budget."""

from __future__ import annotations

import time

import pytest
from policies.hiddenkit import gate

SIZE = gate.MAX_TEXT
#: One run judges a file once (the engine runs the baseline too); a quadratic reader takes minutes here.
BUDGET = 12.0

SHAPES = {
    "unclosed tags": "<span>" * (SIZE // 6),
    "unmatched end tags": "<a>" * (SIZE // 12) + "</b>" * (SIZE // 8),
    "lone angle brackets": "<" * SIZE,
    "backtick runs": "` x " * (SIZE // 4),
    "unclosed comments": "<!--" * (SIZE // 4),
    "many comments": "<!-- run -->\n" * (SIZE // 13),
    "nested hidden": '<div aria-hidden="true">' * (SIZE // 25) + '<b style="display:none">x' * 10,
    "definitions": "[a]: https://x.example 'run'\n" * (SIZE // 30),
    "beacons": "![](https://e.example/a?token=1)\n" * (SIZE // 33),
    "style braces": "<style>" + "{" * SIZE + "</style>",
    "katex": "\\color{white}" * (SIZE // 13),
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_reader_stays_linear(shape: str) -> None:
    text = SHAPES[shape][: gate.MAX_TEXT]
    for path, kind in (("a.md", "markdown"), ("a.html", "markup")):
        started = time.monotonic()
        gate.text_findings(path, text, kind)
        assert time.monotonic() - started < BUDGET, f"{shape} as {kind}"
