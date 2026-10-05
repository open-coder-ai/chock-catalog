"""registry.yaml: every row's label is derived, and its description's first sentence agrees with it."""

from __future__ import annotations

import re

import gen_registry
import pytest
import yaml
from trees import ROOT

ROWS = yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))["policies"]
KEYWORDS = ("block", "ask", "warn", "advise")
#: Words the first sentence must (`need`) or must not (`ban`) carry, per Claude Code keyword.
ADVISE_VERBS = ("blocks", "refuses", "refuse", "denies", "stops", "prevents", "warns")
RULES = {
    "advise": {"ban": ADVISE_VERBS},
    "warn": {"need": ("warn", "warns", "warning")},
    "block": {"ban": ("warns", "would block", "observe")},
    "ask": {"need": ("ask", "asks", "confirm")},
}


def first_sentence(description: str) -> str:
    """The description's first sentence, counted after a leading `Deprecated: ...` one."""
    sentences = re.split(r"\.\s+", " ".join(description.split()))
    skip = 1 if sentences[0].lower().startswith("deprecated:") and len(sentences) > 1 else 0
    return sentences[skip]


def has(sentence: str, words: tuple[str, ...]) -> list[str]:
    return [w for w in words if re.search(rf"\b{re.escape(w)}\b", sentence, re.I)]


@pytest.mark.parametrize("row", ROWS, ids=[r["id"] for r in ROWS])
def test_label_block_is_present(row):
    claude = row.get("label", {}).get("claude-code")
    assert claude and claude["keyword"] in KEYWORDS, f"{row['id']}: no valid label.claude-code"


@pytest.mark.parametrize("row", ROWS, ids=[r["id"] for r in ROWS])
def test_first_sentence_agrees_with_label(row):
    keyword = row["label"]["claude-code"]["keyword"]
    rule, sentence = RULES[keyword], first_sentence(row["description"])
    found = has(sentence, rule.get("ban", ()))
    assert not found, f"{row['id']} is {keyword} on Claude Code but its first sentence says {found}: {sentence!r}"
    if "need" in rule:
        assert has(sentence, rule["need"]), f"{row['id']} is {keyword} on Claude Code; say so: {sentence!r}"


def test_rows_checked():
    assert len(ROWS) == len({r["id"] for r in ROWS}) > 0


def test_a_row_rendered_without_a_label_keeps_the_one_it_had():
    row = gen_registry.facts(ROOT / ROWS[0]["path"])
    old = ["- id: x", "  label:", "    misses: null", "  description: d"]
    assert gen_registry.render_row(row, old)[len(gen_registry.FIELDS) + 1 :][:2] == ["  label:", "    misses: null"]
    assert "  label:" not in gen_registry.render_row(row, ["- id: x"])
