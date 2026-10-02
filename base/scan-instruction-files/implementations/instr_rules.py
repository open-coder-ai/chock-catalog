"""The scan-instruction-files lexicon: a dated data table of regular expressions over casefolded text, checked
and compiled once. A table that is missing, stale-shaped or holds a pattern that does not compile raises."""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from chock_scan import data_table
from instr_text import Statement

ASK, BLOCK = "ask", "block"
VERDICTS = frozenset({ASK, BLOCK})
PATTERN_KEYS = frozenset(
    {
        "negation",
        "encourager",
        "clause_break",
        "send_verb",
        "destination",
        "secret_strong",
        "secret_generic",
        "net_tool",
        "shell_carrier",
        "dns_exfil",
        "fake_trust_close",
        "guard_mandate",
        "guard_topic",
        "exec_marker",
    }
)
RULE_KEYS = frozenset({"id", "verdict", "discount", "label", "phrase", "target"})
LEXICON = Path(__file__).resolve().parent / "data" / "lexicon.json"


class Rule(NamedTuple):
    id: str
    verdict: str
    discount: bool
    label: str
    phrase: re.Pattern[str]
    target: re.Pattern[str] | None


class Hit(NamedTuple):
    """A rule that fired on a statement: its id, verdict and label, and the statement it fired on."""

    rule: str
    verdict: str
    label: str
    statement: Statement


def _problems(doc: dict) -> list[str]:
    """Every problem in the lexicon's payload; a pattern that does not compile is one."""
    out = []
    patterns, rules = doc["patterns"], doc["rules"]
    if not isinstance(patterns, dict) or set(patterns) != PATTERN_KEYS:
        out.append(f"patterns must have exactly the keys {sorted(PATTERN_KEYS)}")
    else:
        out += [f"patterns.{k}: {e}" for k, v in patterns.items() if (e := _compile_error(v, required=True))]
    if not isinstance(rules, list) or not rules:
        return [*out, "rules must be a non-empty list"]
    for n, rule in enumerate(rules):
        if not isinstance(rule, dict) or set(rule) != RULE_KEYS:
            out.append(f"rules[{n}] must have exactly the keys {sorted(RULE_KEYS)}")
            continue
        if rule["verdict"] not in VERDICTS or not isinstance(rule["discount"], bool):
            out.append(f"rules[{n}]: verdict must be ask or block and discount a boolean")
        if not isinstance(rule["id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", rule["id"]):
            out.append(f"rules[{n}]: id must be a short lower-case slug")
        out += [
            f"rules[{n}].{k}: {e}"
            for k in ("phrase", "target")
            if (e := _compile_error(rule[k], required=k == "phrase"))
        ]
    return out


def _compile_error(pattern: object, *, required: bool) -> str | None:
    if pattern is None and not required:
        return None
    if not isinstance(pattern, str) or not pattern:
        return "must be a non-empty regular expression"
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"does not compile: {exc}"
    return None


class Lexicon:
    """The loaded, compiled lexicon. A broken table raises data_table.TableError: never an empty lexicon."""

    def __init__(self, path: Path = LEXICON) -> None:
        doc = data_table.load(path, kind="curated", schema=1, keys={"note", "patterns", "rules"}, check=_problems)
        self.p = {k: re.compile(v) for k, v in doc["patterns"].items()}
        self.rules = [
            Rule(
                r["id"],
                r["verdict"],
                r["discount"],
                r["label"],
                re.compile(r["phrase"]),
                re.compile(r["target"]) if r["target"] else None,
            )
            for r in doc["rules"]
        ]
