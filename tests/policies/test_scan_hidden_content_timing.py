"""scan-hidden-content: inputs shaped to make a reader quadratic stay linear.

Each shape is judged at an eighth and at half of the 1 MiB file cap: four times the input may take at most
eight times as long (linear is four, quadratic sixteen). The two timings are CPU seconds taken in a child
process outside the coverage tracer, which slows a python loop several times over and unevenly with input
size; this process judges each shape once, small, so the reader's lines stay covered. The 30-second budget itself is held by the gate's per-run
deadline (test_scan_hidden_content_review.py), which reports the files it did not reach instead of
timing out; MAX_SECONDS only catches a run gone far beyond linear.
"""

from __future__ import annotations

import time

import pytest
import untraced
from policies.hiddenkit import gate

SIZE = gate.MAX_TEXT
GROWTH = 8.0
MAX_SECONDS = 20.0

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
    "held hiding elements": "<div hidden><p><b hidden><i>x</div>",
    "rebuilt formatting": "<span hidden><b><i><u>",
}


def run(shape: str, size: int, path: str) -> float:
    """CPU seconds the gate takes to judge `size` bytes of `shape`."""
    unit = SHAPES[shape]
    text = (unit * (size // len(unit) + 1))[:size]
    started = time.process_time()
    gate.findings({"event": "commit", "writes": {path: text}})
    return time.process_time() - started


CHILD = """
import json, sys
from policies import test_scan_hidden_content_timing as t
shape, path = sys.argv[1:3]
print(json.dumps([t.run(shape, t.SIZE // 8, path), t.run(shape, t.SIZE // 2, path)]))
"""


@pytest.mark.parametrize("path", ["a.md", "a.html"])
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_reader_stays_linear(shape: str, path: str) -> None:
    run(shape, SIZE // 8, path)
    small, large = untraced.run(CHILD, shape, path)
    assert large < MAX_SECONDS, f"{shape} in {path}: {large:.1f}s"
    assert large < max(small, 0.05) * GROWTH, f"{shape} in {path}: {small:.2f}s then {large:.2f}s"
