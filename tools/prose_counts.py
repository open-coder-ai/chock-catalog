"""Counts quoted in prose files (SECURITY.md, CONTRIBUTING.md), written from registry.yaml.

A count is written between markers, `<!-- gen:KEY -->48<!-- /gen -->`, and the text between them
belongs to the generator. A count written by hand next to a policy noun fails the check, because
two hand-written counts in these files went stale (twenty-two of forty-two, two script policies).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import yaml
from mechanism import CEILING, EVENT_SCRIPT, GATE, GUARD, NONE

#: The prose files whose counts this module owns.
FILES = ("SECURITY.md", "CONTRIBUTING.md")
MARKER = re.compile(r"<!-- gen:(?P<key>[a-z-]+) -->(?P<value>.*?)<!-- /gen -->", re.S)
_WORDS = (
    "two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen "
    "sixteen seventeen eighteen nineteen twenty thirty forty fifty sixty seventy eighty ninety"
)
#: A number, as digits or words, then up to three words, then a noun that counts policies.
HAND_COUNT = re.compile(
    rf"\b(?:\d+|(?:{'|'.join(_WORDS.split())})(?:-\w+)?)\b(?:[ -][\w`-]+){{0,3}}[ -]"
    r"(?:polic\w*|advisor\w*|enforced[\w-]*|guards?|gates?)\b",
    re.I,
)


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
    for number, line in enumerate(outside.splitlines(), 1):
        if hit := HAND_COUNT.search(line):
            problems.append(f"line {number}: hand-written count {hit.group(0)!r}; use a gen marker")
    return filled, problems


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
