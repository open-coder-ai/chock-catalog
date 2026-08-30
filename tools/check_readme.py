#!/usr/bin/env python3
"""Fail if the README's counts, eval numbers, or links have drifted from the repo.

A README is the first thing an adopter reads and the last thing anyone updates. The numbers
in this one -- how many policies, how many enforce, how many eval cases pass -- are exactly
the claims that would embarrass a project about not overstating enforcement.

Usage:  python tools/check_readme.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

from trees import policy_dirs

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def classify() -> tuple[dict[str, list[str]], dict[str, tuple[int, int]]]:
    kinds: dict[str, list[str]] = {"gate": [], "guard": [], "text": []}
    evals: dict[str, tuple[int, int]] = {}
    for d in policy_dirs():
        manifest = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
        gate = (manifest.get("hook") or {}).get("gate") or {}
        impl = d / "implementations"
        if gate.get("kind"):
            kinds["gate"].append(manifest["id"])
        elif impl.is_dir() and any(impl.glob("*.sh")):
            kinds["guard"].append(manifest["id"])
        else:
            kinds["text"].append(manifest["id"])

        cases = []
        suite = d / "evals" / "suite.yaml"
        if suite.exists():
            loaded = yaml.safe_load(suite.read_text(encoding="utf-8")) or {}
            block = loaded.get("suite") or loaded.get("eval_suite") or {}
            cases = block.get("cases") or block.get("test_cases") or []
        evals[manifest["id"]] = (sum(1 for c in cases if c.get("execute")), len(cases))
    return kinds, evals


#: Number words big enough to be a policy count. Spelled-out counts are the hole every check
#: here fell through: `alt="Thirty-six policies ... twenty advisory"` and the prose "twenty of
#: thirty-six are advisory" both survived a file full of count checks, because every one of them
#: matches digits. Rather than teach each check to read English, the README states counts in
#: digits and this rejects the word form outright.
_NUMBER_WORDS = (
    "eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty "
    "thirty forty fifty sixty seventy eighty ninety hundred"
).split()

#: Only where a number word would BE a count. "one policy" or "a dozen reasons" in ordinary
#: prose is not what this is for.
_COUNT_CONTEXT = ("polic", "advisory", "enforced", "gate", "guard", "eval")


def spelled_out_count_problems(text: str) -> list[str]:
    """Reject counts written as words, because no other check in this file can see them.

    Every count check here matches digits, so a word-form number is invisible to all of them --
    which is exactly how the README came to say "twenty of thirty-six are advisory" against a
    repository with 21 of 37, three lines above a table that says otherwise. Digits are not a
    style preference here; they are the only form the rest of this file can verify.
    """
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        lowered = line.lower()
        for word in _NUMBER_WORDS:
            if not re.search(rf"\b{word}\b", lowered):
                continue
            if any(context in lowered for context in _COUNT_CONTEXT):
                problems.append(
                    f"line {number}: count written as a word (%r) -- use digits, so the count "
                    f"checks in this file can see it:\n      {line.strip()[:96]}" % word
                )
                break
    return problems


def alt_text_problems(text: str) -> list[str]:
    """Every figure's README `alt` must be the figure's own `aria-label`.

    Alt text is not decoration here: it is what a crawler, an LLM retriever and a screen
    reader are told the figure shows, and it is the only part of an image any of them read.
    The SVGs carry a generated `aria-label`; the README carried a hand-typed copy, and the
    copies drifted exactly as hand-typed copies do. Three of the four were wrong when this
    check was written:

      * the hero logo said "Chock logo" -- the wrong project, in the most prominent slot on
        the page;
      * the coverage figure said "Thirty-six policies ... nine enforced-at-commit, seven
        enforced, twenty advisory" against a repository holding 37 / 9 / 7 / 21, and the
        badge checks above could not see it because the numbers were spelled as words;
      * the how-it-works figure named a surface the figure had since renamed.

    Comparing against the SVG rather than against the registry is deliberate: it keeps one
    authority per figure, and the figure's own label is already derived from the repository.
    """
    problems: list[str] = []
    for tag in re.findall(r"<img[^>]*>", text):
        src = re.search(r'src="(docs/[^"]+\.svg)"', tag)
        if not src:
            continue  # badges and remote images have no local label to check against
        path = ROOT / src.group(1)
        if not path.exists():
            continue  # already reported as a missing image above
        want = re.search(r'aria-label="([^"]*)"', path.read_text(encoding="utf-8"))
        if not want:
            problems.append(
                f"{src.group(1)} has no aria-label to check the README against"
            )
            continue
        have = re.search(r'alt="([^"]*)"', tag)
        if not have:
            problems.append(f"{src.group(1)} is embedded with no alt text")
        elif have.group(1) != want.group(1):
            problems.append(
                f"{src.group(1)}: README alt has drifted from the figure's own label\n"
                f"      README: {have.group(1)}\n"
                f"      figure: {want.group(1)}"
            )
    return problems


def main() -> int:
    text = README.read_text(encoding="utf-8")
    kinds, evals = classify()
    total = sum(len(v) for v in kinds.values())
    enforced = len(kinds["gate"]) + len(kinds["guard"])
    problems: list[str] = []

    for label, actual, pattern in (
        ("policy count", total, r"badge/policies-(\d+)-"),
        ("enforced count", enforced, r"badge/enforced-(\d+)-"),
        ("advisory count", len(kinds["text"]), r"badge/advisory-(\d+)-"),
    ):
        found = re.search(pattern, text)
        if not found:
            problems.append(f"{label}: badge missing from README")
        elif int(found.group(1)) != actual:
            problems.append(f"{label}: README says {found.group(1)}, repo has {actual}")

    # The advisory row was absent here until 2026-08-30, so the README carried `20` against a
    # repository holding 21 and nothing noticed. A ladder that checks two of its three rows is
    # not checking the ladder.
    for row, want in (
        ("enforced-at-commit", len(kinds["gate"])),
        ("`in-agent`", len(kinds["guard"])),
        ("`advisory`", len(kinds["text"])),
    ):
        found = re.search(
            rf"\| `?{re.escape(row.strip('`'))}`? \|[^|]*\|\s*(\d+) \|", text
        )
        if found and int(found.group(1)) != want:
            problems.append(
                f"ladder row {row}: README says {found.group(1)}, repo has {want}"
            )

    for policy_id, (executed, count) in evals.items():
        found = re.search(
            rf"`{re.escape(policy_id)}`\]\([^)]*\)[^|]*\|[^|]*\|\s*(\d+)/(\d+)\s*\|",
            text,
        )
        if found and (int(found.group(1)), int(found.group(2))) != (executed, count):
            problems.append(
                f"{policy_id}: README says {found.group(1)}/{found.group(2)}, suite has {executed}/{count}"
            )

    for link in re.findall(r"\]\((docs/[^)#]*)\)", text):
        if not (ROOT / link).exists():
            problems.append(f"broken link: {link}")

    for src in re.findall(r'src="(docs/[^"]+)"', text):
        if not (ROOT / src).exists():
            problems.append(f"missing image: {src}")

    problems += alt_text_problems(text)
    problems += spelled_out_count_problems(text)

    # Every policy directory must be reachable from the README.
    for policy_id in sorted(sum(kinds.values(), [])):
        if f"`{policy_id}`" not in text:
            problems.append(f"{policy_id} is published but not mentioned in the README")

    if problems:
        print("README does not match the repo:")
        for p in problems:
            print(f"  {p}")
        return 1
    print(
        f"README matches: {total} policies, {enforced} enforced, {len(kinds['text'])} advisory."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
