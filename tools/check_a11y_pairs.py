#!/usr/bin/env python3
"""Replay the hardening review's regression and correct-work pairs through the shipped guard and count both directions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from check_a11y_rules import load_guard

PAIRS = Path(__file__).resolve().parent / "a11y_fixtures" / "review_pairs.json"
#: Regressions the review marked CAUGHT that stop blocking by ruling: a name lost while an element
#: moves to another file was caught only by refusing every new element. They become warnings.
RULED_TO_WARN = ("R35", "R37")
#: Correct work the review saw refused for being a new element, a new file, or a short lang.
SILENT_AT_BLOCK = (
    *(f"N{n}" for n in (27, 28, 29, 30)),
    *(f"N{n}" for n in range(37, 51)),
    "P01", "P02", "P03",
)  # fmt: skip


def load_pairs() -> list[dict]:
    return json.loads(PAIRS.read_text(encoding="utf-8"))


def verdict(flags: tuple[bool, bool]) -> str:
    """The one word a pair's `expect` is compared with, from (blocked, warned)."""
    blocked, warned = flags
    return "block" if blocked else "warn" if warned else "silent"


def verdicts(guard: object, pair: dict) -> tuple[bool, bool]:
    """(blocked, warned) as a commit would judge it: each staged markup file, deletions excluded."""
    blocked = warned = False
    for path, text in pair["files"].items():
        if not path.endswith(guard.MARKUP_SUFFIXES) or not text["after"]:
            continue
        for row in guard.evaluate(text["before"], text["after"]):
            blocked |= row["action"] == guard.DENY
            warned |= row["action"] == getattr(guard, "WARN", None)
    return blocked, warned


def measure(guard: object) -> dict:
    """Counts per direction, and the ids behind them."""
    seen = {p["id"]: (p, *verdicts(guard, p)) for p in load_pairs()}
    regressions = [i for i, (p, *_) in seen.items() if p["kind"] == "regression" and i.startswith("R")]
    correct = [i for i, (p, *_) in seen.items() if p["kind"] == "correct" and i.startswith("N")]
    probes = [i for i, (p, *_) in seen.items() if p["kind"] == "correct" and i.startswith("P")]
    return {
        "seen": seen,
        "regressions": regressions,
        "correct": correct,
        "caught": [i for i in regressions if seen[i][1]],
        "refused": [i for i in correct if seen[i][1]],
        "probes": probes,
        "probes_refused": [i for i in probes if seen[i][1]],
    }


def check(guard: object) -> list[str]:
    m = measure(guard)
    seen, failures = m["seen"], []

    def swaps(kind: str) -> list[str]:
        return [i for i, (p, *_) in seen.items() if p["kind"] == kind]

    failures += [f"{i}: correct work refused at block" for i in SILENT_AT_BLOCK if seen[i][1]]
    for i in RULED_TO_WARN:
        if seen[i][1]:
            failures.append(f"{i}: still blocks, ruling is that it warns")
        if not seen[i][2]:
            failures.append(f"{i}: no warning is recorded for it")
    # Every regression the review marks CAUGHT, other than the two ruled to warn, is still caught.
    failures += [
        f"{i}: a regression the review marks caught is allowed"
        for i in m["regressions"]
        if seen[i][0]["reviewed"] == "caught" and i not in RULED_TO_WARN and not seen[i][1]
    ]
    # An element replaced by one of its tag that lost the name is a lost name, whatever else changed.
    failures += [
        f"{i}: a named element swapped for an unnamed one is allowed"
        for i in swaps("swap_regression")
        if not seen[i][1]
    ]
    failures += [f"{i}: a swap that keeps the name is refused" for i in swaps("swap_correct") if seen[i][1]]
    for i in swaps("swap_added"):
        if seen[i][1] or not seen[i][2]:
            failures.append(f"{i}: a genuinely added unnamed element must warn and not block")
    # Every pair says what the guard must do with it; `reviewed` stays the review's record, not the rule.
    failures += [
        f"{i}: the guard says {verdict((b, w))}, the pair expects {p['expect']}"
        for i, (p, b, w) in seen.items()
        if verdict((b, w)) != p["expect"]
    ]
    return failures


def main() -> int:
    guard = load_guard()
    m = measure(guard)
    print(
        f"caught {len(m['caught'])} of {len(m['regressions'])}; correct work refused "
        f"{len(m['refused'])} of {len(m['correct'])}; probes refused {len(m['probes_refused'])} of {len(m['probes'])}"
    )
    print(f"refused: {' '.join(m['refused'])} {' '.join(m['probes_refused'])}".rstrip())
    failures = check(guard)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
