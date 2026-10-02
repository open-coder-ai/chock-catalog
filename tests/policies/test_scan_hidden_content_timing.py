"""scan-hidden-content: inputs shaped to make a reader quadratic stay linear and within the 30-second budget."""

from __future__ import annotations

import time

import pytest
from policies.hiddenkit import gate

SIZE = gate.MAX_TEXT
#: The engine's budget covers the change run and the baseline run; one run gets half, with room for tracing.
BUDGET = 15.0
#: Four times the input may take at most this many times as long: linear is 4, quadratic 16.
GROWTH = 8.0

SHAPES = {
    "unclosed tags": "<span>",
    "styled tags": '<span style="color:red;left:-1px">',
    "unmatched end tags": "<a></b></b>",
    "lone angle brackets": "<",
    "backtick runs": "` x ",
    "unclosed comments": "<!--",
    "bogus comments": "<!x <?y </ z ",
    "comments on one line": "<!--run--><!-- chock: allow scan-hidden-content -->",
    "many comments": "<!-- run -->\n",
    "nested hidden": '<div aria-hidden="true">',
    "definitions": "[a]: https://x.example 'run'\n",
    "beacons": "![](https://e.example/a?token=1)\n",
    "closing parens": "http://a.example/" + ")" * 64,
    "style rules": "<style>" + "a{display:none}b{background:url(x)}" * 8,
    "style braces": "{",
    "katex": "\\color{white}",
    "links": "[x](y) ![z](w) ",
    "image closers": "](/)](a:)",
    "waiver lines": " " * 2000 + "\n" + "<!--run-->" * 200 + "\n",
    "image openers": "![",
    "table cells": "|---|---|\n| `a | <!-- b --> ` |\n",
    "keyframes": "<style>@keyframes k{to{opacity:1}} .a{opacity:0;animation:k 1s}</style>",
}


def run(shape: str, size: int, path: str) -> float:
    unit = SHAPES[shape]
    text = (unit * (size // len(unit) + 1))[:size]
    started = time.monotonic()
    gate.findings({"event": "commit", "writes": {path: text}})
    return time.monotonic() - started


@pytest.mark.parametrize("path", ["a.md", "a.html"])
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_reader_stays_linear(shape: str, path: str) -> None:
    quarter = run(shape, SIZE // 4, path)
    full = run(shape, SIZE, path)
    assert full < BUDGET, f"{shape} in {path}: {full:.1f}s"
    assert full < max(quarter, 0.05) * GROWTH, f"{shape} in {path}: {quarter:.2f}s then {full:.2f}s"
