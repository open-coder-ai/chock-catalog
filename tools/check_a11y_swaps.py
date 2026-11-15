#!/usr/bin/env python3
"""Fail if the shipped guard lets a named element be swapped for an unnamed one."""

from __future__ import annotations

import sys

from check_a11y_rules import load_guard
from check_a11y_table import Cases


def check_a_swap_that_loses_the_name(c: Cases) -> None:
    """The key an edit changes must not hide a lost name: a named element replaced by an unnamed one blocks."""
    named, bare = '<img src="a.png" alt="Team">', '<img src="b.png">'
    c.refused("an image swapped, alt dropped", named, bare)
    c.refused("two tags swapped in one stretch", f'{named}<button aria-label="Close"></button>', f'{bare}<button class="x"></button>')
    c.silent("an image swapped, alt kept", named, '<img src="b.png" alt="Team">')
    c.warned("an unnamed image added beside the named one", named, f"{named}{bare}")
    rows = c.rows(named, f'{bare}<img src="c.png">')
    c.expect(
        c.alarms(rows) == ["img[src=b.png]"] and c.warnings(rows) == ["img[src=c.png]"],
        "the image in the lost one's place blocks and the extra one only warns",
    )


def main() -> int:
    cases = Cases(load_guard())
    check_a_swap_that_loses_the_name(cases)
    for failure in cases.failures:
        print(f"  - {failure}", file=sys.stderr)
    if not cases.failures:
        print(f"A swap that loses the name blocks: {cases.checked} cases.")
    return 1 if cases.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
