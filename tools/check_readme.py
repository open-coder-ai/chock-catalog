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
    "two three four five six seven eight nine ten "
    "eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty "
    "thirty forty fifty sixty seventy eighty ninety hundred"
).split()

#: The nouns a count here would be counting. "one" is deliberately absent from the words
#: above: it is overwhelmingly ordinary prose ("one policy at a time"), and a catalog will
#: never legitimately report a total of one.
_COUNT_NOUNS = r"polic\w*|advisor\w*|enforced[\w-]*|in-agent|gate\w*|guard\w*|eval\w*"


#: Each per-tier table and the registry field whose policies it must list in full.
#:
#: Both enforcing tiers are here. `text` (advisory) deliberately is not: its 21 policies are
#: not one table -- they are split across the Compliance and Agentic security sections by
#: subject, so "every advisory policy is a row under Advisory" is simply not true of this
#: README's structure, and asserting it would be a permanent false alarm rather than a check.
_TIER_SECTIONS = (
    ("Enforced at commit", "gate"),
    ("Enforced before the tool runs", "guard"),
)


def tier_table_problems(text: str, kinds: dict) -> list[str]:
    """A per-tier table must list every policy of that tier, not merely some of them.

    The existing "published but not mentioned in the README" check below is satisfied by a
    mention anywhere -- a policy named in a prose paragraph passes it while being absent from
    the table that enumerates its tier. That is how the `Enforced at commit` table came to
    show six rows under a summary saying nine: `block-wildcard-iam`,
    `block-unpinned-agent-components` and `block-unsafe-code-execution` were each mentioned
    elsewhere on the page and listed nowhere a reader counting the tier would look.
    """
    problems = []
    for heading, kind in _TIER_SECTIONS:
        section = re.search(
            # `\Z` matters: without it a section that is the last thing in the file matches
            # nothing and gets reported as missing, which is a false alarm wearing the wrong
            # error message.
            rf"\*\*{re.escape(heading)}\*\*.*?(?=\n\*\*[A-Z]|\n## |\Z)",
            text,
            re.S,
        )
        if not section:
            problems.append(f"the '{heading}' section is missing from the README")
            continue
        if kind not in kinds:
            # A mistake in _TIER_SECTIONS, not repository drift -- but reported rather than
            # raised, so one bad entry cannot take down every other check in this file.
            problems.append(
                f"'{heading}' is configured against unknown policy kind {kind!r}"
            )
            continue
        listed = re.findall(r"^\| \[`([^`]+)`\]", section.group(0), re.M)
        # Membership alone is not enough: a policy listed twice satisfies "every assigned
        # policy appears" AND "everything here is assigned", while the table shows one more
        # row than the summary claims -- the same count-disagreement this whole check exists
        # to catch, hiding inside the check meant to catch it.
        for policy_id in sorted(set(listed)):
            if listed.count(policy_id) > 1:
                problems.append(
                    f"{policy_id} is listed {listed.count(policy_id)} times under '{heading}'"
                )
        for policy_id in sorted(kinds[kind]):
            if policy_id not in listed:
                problems.append(
                    f"{policy_id} is a `{kind}` policy but is not a row under '{heading}'"
                )
        for policy_id in listed:
            if policy_id not in kinds[kind]:
                problems.append(
                    f"{policy_id} is listed under '{heading}' but is not a `{kind}` policy"
                )
    return problems


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
            # Adjacency, not "anywhere on the line": a number word three words from a count
            # noun is a count ("twenty of thirty-six are advisory"), one paragraph away is
            # not. Line-wide matching flagged prose that merely shared a line with the word
            # "policy", which is how a lint earns itself a suppression comment.
            if re.search(
                rf"\b{word}\b(?:[ -]\w+){{0,3}}[ -](?:{_COUNT_NOUNS})\b", lowered
            ):
                problems.append(
                    f"line {number}: count written as a word ({word!r}) -- use digits, so "
                    f"the count checks in this file can see it:"
                    f"\n      {line.strip()[:96]}"
                )
                break
    return problems


def _alt_value(match: re.Match) -> str:
    """The alt text, from whichever quote style the tag used. Empty is a value, not a miss."""
    return match.group("dq") if match.group("dq") is not None else match.group("sq")


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
    # Not `<img[^>]*>`: that stops at the first `>`, so an alt containing one truncates the
    # tag, the `src=` falls outside the match, and the image escapes checking altogether --
    # silently, which is the worst way for a check to fail. Attribute values are skipped over
    # as quoted units instead.
    for tag in re.findall(r"""<img(?:[^>"']|"[^"]*"|'[^']*')*>""", text):
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
        have = re.search(r"""alt=(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""", tag)
        if not have:
            problems.append(f"{src.group(1)} is embedded with no alt text")
        elif _alt_value(have) != want.group(1):
            problems.append(
                f"{src.group(1)}: README alt has drifted from the figure's own label\n"
                f"      README: {_alt_value(have)}\n"
                f"      figure: {want.group(1)}"
            )
    return problems


def main() -> int:
    """Check every claim the README makes about this repository against the repository.

    Collects problems rather than failing at the first, so one run tells you everything that
    has drifted. The checks accumulate as defects are found: badge counts, ladder rows and
    per-policy eval counts came first; alt text against each figure's own label, counts
    written as words, and per-tier table completeness were each added after a real defect
    walked past everything already here.
    """
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
        # findall, not search: `search` stops at the first row, so a second row for the same
        # tier -- with a different count, contradicting the first three lines below it -- was
        # accepted as valid. Two rows disagreeing is worse than one row wrong, because a
        # reader cannot tell which is meant.
        rows = re.findall(
            # EVERY newline-permitting construct on this line has to be closed, not just the
            # obvious one. `[^|]` is a negated class so it matches newlines -- but so does
            # `\s`, and closing only the first still let `| row | text |` followed by a line
            # starting `21 |` read 21 as this row's count. A malformed table whose stray
            # number happens to equal the true count then passes as valid: a silent
            # wrong-pass on broken markup. `[^\r\n|]` for cells, `[ \t]` for padding.
            rf"\| `?{re.escape(row.strip('`'))}`? \|[^\r\n|]*\|[ \t]*(\d+)[ \t]*\|",
            text,
        )
        if len(rows) > 1:
            problems.append(
                f"ladder row {row}: appears {len(rows)} times, saying {', '.join(rows)}"
            )
            continue
        found = re.match(r"(\d+)", rows[0]) if rows else None
        if not found:
            # Previously `if found and ...`, so deleting a row entirely silenced its check --
            # the one edit most likely to be made when a count becomes inconvenient.
            problems.append(f"ladder row {row}: missing from the README")
        elif int(found.group(1)) != want:
            problems.append(
                f"ladder row {row}: README says {found.group(1)}, repo has {want}"
            )

    for policy_id, (executed, count) in evals.items():
        found = re.search(
            # Same row-scoping as the ladder pattern above, for the same reason.
            rf"`{re.escape(policy_id)}`\]\([^)]*\)[^\r\n|]*\|[^\r\n|]*\|[ \t]*(\d+)/(\d+)[ \t]*\|",
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
    problems += tier_table_problems(text, kinds)

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
