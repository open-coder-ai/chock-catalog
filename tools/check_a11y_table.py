#!/usr/bin/env python3
"""Fail if the shipped accessibility guard's decision table or its parser judges markup wrongly."""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

from check_a11y_rules import load_guard

FIXTURES = Path(__file__).resolve().parent / "a11y_fixtures"


class Cases:
    """Collects every disagreement rather than stopping at the first."""

    def __init__(self, guard: object) -> None:
        self.g = guard
        self.failures: list[str] = []
        self.checked = 0

    def rows(self, before: str, after: str) -> dict[str, dict]:
        return {row["ref"]: row for row in self.g.evaluate(before, after)}

    def fixture(self, before: str, after: str) -> dict[str, dict]:
        read = [(FIXTURES / name).read_text(encoding="utf-8") for name in (before, after)]
        return self.rows(*read)

    def alarms(self, rows: dict[str, dict]) -> list[str]:
        return sorted(ref for ref, row in rows.items() if row["action"] == self.g.DENY)

    def expect(self, condition: bool, complaint: str) -> None:
        self.checked += 1
        if not condition:
            self.failures.append(complaint)

    def silent(self, label: str, before: str, after: str) -> None:
        """Correct markup, from every direction this parser can be shown it."""
        alarms = self.alarms(self.rows(before, after))
        self.expect(not alarms, f"{label}: refused a correct change ({', '.join(alarms)})\n      {after}")

    def refused(self, label: str, before: str, after: str) -> None:
        self.expect(bool(self.alarms(self.rows(before, after))), f"{label}: allowed a break\n      {after}")


def check_the_table_is_total(c: Cases) -> None:
    """Seven states, forty-nine cells. A missing cell is a KeyError, never a silent pass."""
    states = (c.g.SATISFIED, c.g.SUPPRESSED, c.g.MISSING, c.g.GONE, c.g.EXEMPT, c.g.UNEVALUATED, c.g.NAMELESS)
    c.expect(set(itertools.product(states, states)) == set(c.g.TABLE), "the table is not every pair of states")
    c.expect(len(c.g.TABLE) == 49, f"the table has {len(c.g.TABLE)} cells, not 49")
    for state in states:
        # The asymmetry that makes a per-framework component registry unnecessary, as a property.
        c.expect(
            c.g.TABLE[(c.g.NAMELESS, state)][0] == c.g.SILENT,
            f"(nameless, {state}) can raise an alarm; absence of a name must prove nothing",
        )


def check_a_patch_at_scale(c: Cases) -> None:
    """The scale claim: a patch that fixes 38 images puts no question to anybody."""
    rows = c.fixture("before-scale.html", "after-scale.html")
    fixed = [r for r in rows.values() if r["key"] == (c.g.MISSING, c.g.SATISFIED) and r["action"] == c.g.RECORD]
    c.expect(len(fixed) == 38, f"{len(fixed)} correct fixes were recorded, not 38")
    c.expect(
        c.alarms(rows) == ["html:1", "img[src=/chart.png]", "img[src=/product-39.png]", "img[src=/product-40.png]"],
        f"the alarms on the scale fixture are {c.alarms(rows)}",
    )
    c.expect(
        "placeholder wording" in rows["img[src=/product-39.png]"]["why"],
        "a fix supplying a placeholder word was not named as one",
    )
    # lang on <html> proves the table generalises past accessible names with no new code.
    c.expect(c.g.REQUIRED["html"]["needs"] == "lang", "the requirement table no longer carries lang")


def check_no_change_no_alarm(c: Cases) -> None:
    """The invariant that matters most. It caught a real bug once."""
    for name in ("before.html", "after.html", "before-scale.html", "edge-before.html"):
        text = (FIXTURES / name).read_text(encoding="utf-8")
        c.silent(f"{name} against itself", text, text)
    rows = c.fixture("before.html", "after.html")
    for ref in ("button[data-testid=dismiss]", "a[href=/details]", "button[data-testid=save]"):
        c.expect(rows[ref]["action"] == c.g.SILENT, f"{ref}: a copy change or a new element was not silent")


def check_the_requirement_qualifiers(c: Cases) -> None:
    """only_when and by_type: an element outside its rule's condition carries no requirement."""
    rows = c.fixture("edge-before.html", "edge-after.html")
    for ref, key, why in (
        ("a[name=section-top]", (c.g.EXEMPT, c.g.EXEMPT), "an <a> with no href is not a link"),
        ("input[name=csrf]", (c.g.EXEMPT, c.g.EXEMPT), "input[type=hidden] needs no name"),
        ("input:2", (c.g.SATISFIED, c.g.SATISFIED), "input[type=submit] is named by its value"),
    ):
        c.expect(rows[ref]["key"] == key, f"{ref} read {rows[ref]['key']} and not {key} -- {why}")


def check_a_name_the_subtree_carries(c: Cases) -> None:
    """accname computes a name from the whole subtree, so an icon link is named, not unnamed."""
    c.silent("an svg named by its title child", "<p>x</p>", '<svg role="img"><title>Quarterly revenue</title></svg>')
    c.refused("an svg with no title child", "<p>x</p>", '<svg role="img"></svg>')
    c.silent("a link named by its icon's title", "<p>x</p>", '<a href="/home"><svg role="img"><title>Home</title></svg></a>')
    for markup in (
        '<a href="/home"><img src="/i.png" alt="Home"></a>',
        '<button><img src="/x.png" alt="Close"></button>',
        '<h2><img src="/l.png" alt="Acme"></h2>',
    ):
        c.silent("an element named by its child image", "<p>x</p>", markup)
    # "legend-text" is narrower than "text": stray descendant text must not name a fieldset.
    c.refused("a fieldset with no legend", "<p>x</p>", "<fieldset><p>Address</p></fieldset>")
    # And the unevaluated channel must not swallow the case it was carved out of.
    c.refused("a genuinely empty link", "<p>x</p>", '<a href="/x"></a>')


def check_what_the_parser_cannot_resolve(c: Cases) -> None:
    """A name this parser cannot follow is not a missing name. Refusing it fires on correct code."""
    for markup in (
        '<a href="/x"><Icon /></a>',
        '<button><FormattedMessage id="close" /></button>',
        "<img {...imgProps} />",
        '<img src="/a.png" alt={logo} />',
        '<img src="/a.png" alt="{{ logo }}" />',
    ):
        c.silent("markup this parser cannot resolve", "<p>x</p>", markup)
    # A template placeholder is not a name either, whichever syntax spells it. `__ALT__` was
    # refused as placeholder wording while `{alt}` passed -- and a correct extraction into a
    # parameterised partial is exactly where __TOKEN__ appears.
    for token in ("__ALT__", "__DESCRIPTION__", "__LABEL__", "__TITLE__"):
        c.silent(f"a {token} placeholder", '<img src="__IMG__">', f'<img src="__IMG__" alt="{token}">')
    # The name moving somewhere this parser cannot follow is not the name being removed.
    c.silent(
        "a name moved into a child component",
        '<Image id="i" alt="Acme logo" />',
        '<Image id="i"><Caption>Acme logo</Caption></Image>',
    )


def check_quality_is_judged_only_on_a_fix(c: Cases) -> None:
    """A pre-existing weak name is not this change's business; judging it fails innocent commits."""
    weak = '<html lang="en"><img src="/a.png" alt="image"></html>'
    c.silent("an untouched weak name", weak, weak)
    c.refused("a fix that supplies a weak name", '<html lang="en"><img src="/a.png"></html>', weak)
    for text in ("click here", "read more", "learn more", "this link", "more info"):
        c.refused(f"a link named {text!r}", '<a href="/x"></a>', f'<a href="/x">{text}</a>')
    for markup in ("<button>Continue</button>", "<button>More options</button>"):
        c.silent("a button label that is honest", "<p>x</p>", markup)


def check_components(c: Cases) -> None:
    """A component is not the HTML element it shadows, and absence of a name proves nothing."""
    for markup in (
        '<Button label="Save" />',
        '<Input label="Email" />',
        '<Select label="Country" />',
        '<Table caption="Revenue by quarter" />',
        '<Form label="Signup" />',
    ):
        c.silent("a component shadowing an HTML name", "<p>x</p>", markup)
    for markup in ('<Thumbnail src="/t.png" />', "<Spacer />", '<Chart data="{d}" />'):
        c.silent("a new component with no name", "<p>x</p>", markup)
    c.silent("an unnamed component edited", '<Chart data="{a}" />', '<Chart data="{b}" />')
    for before, after in (
        ('<Image src="/l.png" alt="Acme logo" />', '<Image src="/l.png" alt="" />'),
        ('<Avatar src="/u.png" alt="Jane Doe" />', '<Avatar src="/u.png" />'),
        ('<IconButton id="x" aria-label="Close" />', '<IconButton id="x" />'),
        ('<el-image src="/c.png" alt="Revenue" />', '<el-image src="/c.png" alt="" />'),
        ('<Button id="s" label="Save draft" />', '<Button id="s" label="" />'),
    ):
        c.refused("a component losing a name it carried", before, after)


def main() -> int:
    try:
        guard = load_guard()
    except Exception as exc:  # noqa: BLE001 -- any import failure is the same answer: unrunnable
        print(f"Cannot load the shipped guard: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    cases = Cases(guard)
    for check in (
        check_the_table_is_total,
        check_a_patch_at_scale,
        check_no_change_no_alarm,
        check_the_requirement_qualifiers,
        check_a_name_the_subtree_carries,
        check_what_the_parser_cannot_resolve,
        check_quality_is_judged_only_on_a_fix,
        check_components,
    ):
        check(cases)

    if cases.failures:
        print(f"The decision table or the parser misjudges markup ({len(cases.failures)} of {cases.checked}):",
              file=sys.stderr)
        for failure in cases.failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nFix the guard, never the case. A break allowed here is a break this gate misses; a "
            "correct change refused here is worse, because the gate blocks commits and the markup "
            "was right.",
            file=sys.stderr,
        )
        return 1

    print(f"The decision table holds: {cases.checked} cases over {len(guard.TABLE)} table cells.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
