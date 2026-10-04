"""scan-hidden-content: the inputs the timing test builds, and the readings the Markdown gate takes of them."""

from __future__ import annotations

import pytest
from policies import test_scan_hidden_content_timing as timing
from policies.hiddenkit import readers

readings, spans = readers["readings"], readers["spans"]
#: readings.markdown: 2 views x 2 HTML forms, plus 2 flat, 2 inline and 2 liberal readings at most.
MAX_READINGS = 10
LARGE = timing.SIZE // 2
SMALL = timing.SIZE // 8


@pytest.mark.parametrize("shape", sorted(timing.SHAPES))
def test_large_input_is_the_old_cut(shape: str) -> None:
    unit = timing.SHAPES[shape]
    assert timing.text_of(shape, LARGE) == (unit * (LARGE // len(unit) + 1))[:LARGE]


@pytest.mark.parametrize("shape", sorted(timing.SHAPES))
def test_sizes_end_on_the_same_partial_unit(shape: str) -> None:
    unit = timing.SHAPES[shape]
    small, large = timing.text_of(shape, SMALL), timing.text_of(shape, LARGE)
    tail = LARGE % len(unit)
    assert small[len(small) - tail :] == large[len(large) - tail :] == unit[:tail]
    assert SMALL - len(unit) < len(small) <= SMALL
    assert LARGE - len(unit) < len(large) <= LARGE


@pytest.mark.parametrize("shape", sorted(timing.SHAPES))
def test_markdown_readings_are_bounded(shape: str) -> None:
    text = timing.text_of(shape, 4096)
    tags = spans.tag_view(text, spans.blank_code(text))
    assert 1 <= len(readings.markdown(text, tags)) <= MAX_READINGS
