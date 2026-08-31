#!/usr/bin/env python3
"""Fail if the README's counts, eval numbers, or links have drifted from the repo."""

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


_NUMBER_WORDS = (
    "two three four five six seven eight nine ten "
    "eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty "
    "thirty forty fifty sixty seventy eighty ninety hundred"
).split()

_COUNT_NOUNS = r"polic\w*|advisor\w*|enforced[\w-]*|in-agent|gate\w*|guard\w*|eval\w*"


_TIER_SECTIONS = (
    ("Enforced at commit", "gate"),
    ("Enforced before the tool runs", "guard"),
)


def tier_table_problems(text: str, kinds: dict) -> list[str]:
    """A per-tier table must list every policy of that tier, not merely some of them."""
    problems = []
    for heading, kind in _TIER_SECTIONS:
        section = re.search(
            rf"\*\*{re.escape(heading)}\*\*.*?(?=\n\*\*[A-Z]|\n## |\Z)",
            text,
            re.S,
        )
        if not section:
            problems.append(f"the '{heading}' section is missing from the README")
            continue
        if kind not in kinds:
            problems.append(
                f"'{heading}' is configured against unknown policy kind {kind!r}"
            )
            continue
        listed = re.findall(r"^\| \[`([^`]+)`\]", section.group(0), re.M)
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
    """Reject counts written as words, because no other check in this file can see them."""
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        lowered = line.lower()
        for word in _NUMBER_WORDS:
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
    """Every figure's README `alt` must be the figure's own `aria-label`."""
    problems: list[str] = []
    for tag in re.findall(r"""<img(?:[^>"']|"[^"]*"|'[^']*')*>""", text):
        src = re.search(r'src="(docs/[^"]+\.svg)"', tag)
        if not src:
            continue
        path = ROOT / src.group(1)
        if not path.exists():
            continue
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
    """Check every claim the README makes about this repository against the repository."""
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

    for row, want in (
        ("enforced-at-commit", len(kinds["gate"])),
        ("`in-agent`", len(kinds["guard"])),
        ("`advisory`", len(kinds["text"])),
    ):
        rows = re.findall(
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
            problems.append(f"ladder row {row}: missing from the README")
        elif int(found.group(1)) != want:
            problems.append(
                f"ladder row {row}: README says {found.group(1)}, repo has {want}"
            )

    for policy_id, (executed, count) in evals.items():
        found = re.search(
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
