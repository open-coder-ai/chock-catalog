"""Judge one hunk: a removed guard with no replacement in the hunk, or a removed or weakened mitigation."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from diffshape.hunks import Hunk
from diffshape.shapes import Mitigation, Shapes

GUARD_RULE = "guard-deletion"
MITIGATION_RULE = "mitigation-removal"
#: Longer lines are cut here, so a pathological line cannot make a pattern run long.
MAX_LINE = 1000
COMMENT_ONLY = re.compile(r"^(?:#(?!(?:define|undef)\b)|//|/\*|\*|--|<!--|;(?=\s|$))")
IMPORT_ONLY = re.compile(r"^(?:import|from\s+\S+\s+import|using)\s+[\w.:\\*,{} \t'\"/@-]+;?$")
LEADING_BLOCK = re.compile(r"^(?:/\*.*?\*/|\*/)\s*")
STRINGS = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")
TRAILING_COMMENT = re.compile(r"\s(?:#|//|--\s).*$")
#: waived(hunk, the removed lines the finding rests on, rule) -> True when a pragma waives the rule there.
LONG = "split the long line, or have a person review the removal"
Waived = Callable[[Hunk, list[str], str], bool]


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    family: str
    label: str
    advice: str


def code_of(raw: str) -> str:
    """The line without its trailing comment; empty when the whole line is a comment or an import."""
    text = LEADING_BLOCK.sub("", raw.strip()[:MAX_LINE])
    if COMMENT_ONLY.match(text) or IMPORT_ONLY.match(text):
        return ""
    masked = STRINGS.sub(lambda m: "x" * len(m.group()), text)
    cut = TRAILING_COMMENT.search(masked)
    return text[: cut.start()] if cut else text


def _fires(fam: Mitigation, carried: list[int], weaker: list[int], added: list[str]) -> bool:
    """Whether the hunk removes or weakens `fam` and puts nothing back that keeps it."""
    if any(fam.kept.search(code) for code in added):
        return False
    if fam.trigger == "removed":
        return bool(carried)
    return bool(carried or weaker) if fam.trigger == "removed-or-added" else bool(carried and weaker)


def _mitigations(
    hunk: Hunk, shapes: Shapes, waived: Waived, rem: list[str], add: list[str]
) -> tuple[list[Finding], set[int]]:
    """Findings for mitigations the hunk removes or weakens, and the removed lines they account for."""
    found: list[Finding] = []
    handled: set[int] = set()
    for fam in shapes.mitigations:
        carried = [i for i, code in enumerate(rem) if fam.removed.search(code)]
        weaker = [i for i, code in enumerate(add) if fam.weak and fam.weak.search(code)]
        if not _fires(fam, carried, weaker, add):
            continue
        handled.update(carried)
        if waived(hunk, [hunk.removed[i] for i in carried], MITIGATION_RULE):
            continue
        found.append(Finding(MITIGATION_RULE, hunk.path, hunk.line, fam.id, fam.label, fam.fix))
    return found, handled


def _guards(hunk: Hunk, shapes: Shapes, waived: Waived, rem: list[str], add: list[str]) -> list[Finding]:
    """Findings for removed guards whose group has no guard-shaped line among the added lines."""
    removed_hits: dict[str, dict[tuple[str, str], None]] = {}
    for i, code in enumerate(rem):
        guard = next((g for g in shapes.guards if g.pattern.search(code)), None)
        if guard and not waived(hunk, [hunk.removed[i]], GUARD_RULE):
            removed_hits.setdefault(guard.group, {})[(guard.id, guard.label)] = None
    found: list[Finding] = []
    for group, hits in removed_hits.items():
        bare = add if group in ("registration", "tls") else [STRINGS.sub('""', code) for code in add]
        if any(g.group == group and g.pattern.search(code) for g in shapes.guards for code in bare):
            continue
        advice = "keep the check, or put its replacement in the same hunk"
        found += [Finding(GUARD_RULE, hunk.path, hunk.line, fam, label, advice) for fam, label in hits]
    return found


def judge_hunk(hunk: Hunk, shapes: Shapes, waived: Waived) -> list[Finding]:
    """Mitigation findings (block) then guard findings (ask) for one hunk."""
    rem = [code_of(raw) for raw in hunk.removed]
    add = [code_of(raw) for raw in hunk.added]
    mitigation, handled = _mitigations(hunk, shapes, waived, rem, add)
    left = ["" if i in handled else code for i, code in enumerate(rem)]
    found = mitigation + _guards(hunk, shapes, waived, left, add)
    if not found and any(len(raw.strip()) > MAX_LINE for raw in hunk.removed) and not waived(hunk, [], GUARD_RULE):
        found.append(Finding(GUARD_RULE, hunk.path, hunk.line, "long-line", "a removed line too long to read", LONG))
    return found
