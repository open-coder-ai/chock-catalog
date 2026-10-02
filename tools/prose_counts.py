"""Counts quoted in prose files (SECURITY.md, CONTRIBUTING.md), written from registry.yaml.

A count is written between markers, `<!-- gen:KEY -->48<!-- /gen -->`, and the text between them
belongs to the generator. A number written by hand within five words of a policy noun, either
side, fails the check, because two hand-written counts in these files went stale (twenty-two of
forty-two, two script policies). That check is a heuristic backstop for review, not a proof: a
count with no policy noun nearby ("All 48 ship a manifest") still needs a reviewer to ask for a
marker.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import yaml
from mechanism import CEILING, EVENT_SCRIPT, GATE, GUARD, NONE

#: The prose files whose counts this module owns.
FILES = ("SECURITY.md", "CONTRIBUTING.md")
#: One line, no markup inside: an unclosed or nested marker then shows up as a stray one.
MARKER = re.compile(r"<!-- gen:(?P<key>[a-z-]+) -->(?P<value>[^<\n]*)<!-- /gen -->")
#: Any gen token left once the valid markers are gone is a marker spelled some other way.
STRAY = re.compile(r"\bgen\s*:|/\s*gen\b", re.I)
#: Markup a reader does not see, which must not separate a number from its noun.
#: An ordered-list marker ("1." or "**2.**" at the start of a line) numbers an item, not policies.
#: A link target or bare URL is an address, not words (a "%22" in it is a quote, not 22).
_INVISIBLE = re.compile(
    r"<!--.*?-->|</?[A-Za-z][^<>\n]*>|&#?\w+;|(?m:^[ \t>]*[*_]*\d+\.(?=[*_\s]))|\]\([^)\s]*\)|https?://\S+",
    re.S,
)
_NUMBER_WORDS = frozenset(
    {
        *("two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"),
        *("thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"),
        *("thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"),
    }
)
#: Words, and numbers that are not part of a version, an issue (#12) or a decimal.
_TOKEN = re.compile(r"[A-Za-z][\w'\u2019-]*|(?<![#.A-Za-z0-9])\d+(?![.\w]\d)")
_NOUN = re.compile(r"(?:polic|advisor|enforc|best-effort|effort|guard|gate|program)", re.I)
#: How many words either side of a number a policy noun may sit and still make it a count.
WINDOW = 5


def _hook_program(row: dict) -> bool:
    """A policy whose git hook runs a program it ships: a script gate or a git-event script."""
    return row["mechanism"] == "script" or row["mechanism"].startswith("commit-time guard script")


def values(rows: list[dict]) -> dict[str, str]:
    """Every key a marker may name, rendered from the registry rows."""

    def count(keep: Callable[[dict], bool]) -> str:
        return str(sum(1 for row in rows if keep(row)))

    programs = sorted(row["id"] for row in rows if _hook_program(row))
    return {
        "policies": str(len(rows)),
        "advisory": count(lambda row: row["enforces"] == CEILING[NONE]),
        "best-effort": count(lambda row: row["enforces"] == CEILING[GUARD]),
        "enforced-at-commit": count(lambda row: row["enforces"] in (CEILING[GATE], CEILING[EVENT_SCRIPT])),
        "hook-programs": str(len(programs)),
        "hook-program-ids": ", ".join(f"`{pid}`" for pid in programs),
    }


def render(text: str, known: dict[str, str]) -> tuple[str, list[str]]:
    """The text with every marker filled, and what is wrong with it."""
    problems = [f"unknown count marker gen:{key}" for key, _ in MARKER.findall(text) if key not in known]
    if not MARKER.search(text):
        problems.append("no generated count markers (<!-- gen:KEY -->N<!-- /gen -->)")
    filled = MARKER.sub(lambda m: f"<!-- gen:{m['key']} -->{known.get(m['key'], m['value'])}<!-- /gen -->", text)
    outside = MARKER.sub("", filled)
    problems += [f"line {_line(outside, m)}: malformed or unclosed gen marker" for m in STRAY.finditer(outside)]
    visible = _INVISIBLE.sub(lambda m: " " + "\n" * m[0].count("\n"), outside)
    problems += [f"line {line}: hand-written count {near!r}; use a gen marker" for line, near in hand_counts(visible)]
    return filled, problems


def _is_number(token: str) -> bool:
    return token.isdigit() or token.lower().split("-")[0] in _NUMBER_WORDS


def hand_counts(text: str) -> list[tuple[int, str]]:
    """(line, the words around it) for each number with a policy noun within WINDOW words either side."""
    tokens = list(_TOKEN.finditer(text))
    found = []
    for i, token in enumerate(tokens):
        near = tokens[max(0, i - WINDOW) : i + WINDOW + 1]
        if _is_number(token[0]) and any(_NOUN.match(t[0]) for t in near):
            found.append((_line(text, token), " ".join(t[0] for t in near)))
    return found


def _line(text: str, match: re.Match) -> int:
    return text.count("\n", 0, match.start()) + 1


def update(root: Path, *, write: bool) -> list[str]:
    """One line per file: current, stale, rewritten, or what makes it unwritable."""
    rows = yaml.safe_load((root / "registry.yaml").read_text(encoding="utf-8"))["policies"]
    known = values(rows)
    results = []
    for name in FILES:
        path = root / name
        before = path.read_text(encoding="utf-8")
        after, problems = render(before, known)
        if problems:
            results += [f"{name} is stale: {problem}" for problem in problems]
        elif after == before:
            results.append(f"{name} counts already current")
        elif not write:
            results.append(f"{name} is stale: run python tools/gen_registry.py")
        else:
            path.write_text(after, encoding="utf-8", newline="\n")
            results.append(f"{name} counts rewritten")
    return results
