"""Judge one written file: every rule's findings, once each, asked rather than refused under test, fixture and doc paths."""

from __future__ import annotations

import sbf_json
import sbf_keys
import sbf_names
import sbf_text
from chock_scan import entropy
from sbf_core import ASK, KEYS, Finding

#: Policy eval suites carry fixtures too; chock_scan.entropy.path_class names the other downgraded paths.
FIXTURE_SEGMENTS = frozenset({"evals"})


def judge(path: str, text: str) -> list[Finding]:
    """Every finding in one file, in line order; a fixture, doc or lock path turns a refusal into an ask."""
    # The engine decodes UTF-8 and keeps a BOM; a tool-use write keeps CRLF. Both would hide a line start.
    text = text.removeprefix("\ufeff").replace("\r\n", "\n")
    norm = path.replace("\\", "/")
    base = norm.rsplit("/", 1)[-1]
    name = base.lower()
    content = sbf_keys.judge(text)
    named = sbf_names.judge(norm, name, base, text)
    if any(f.rule == KEYS for f in content):  # what the key is (encrypted or not) beats what it is called
        named = [f for f in named if f.rule != KEYS]
    found = [*named, *content, *sbf_text.judge(norm, name, text), *sbf_json.judge(text, name)]
    if downgraded(norm):
        found = [f._replace(level=ASK) for f in found]
    return sorted(set(found), key=lambda f: (f.line, f.rule, f.what))


def downgraded(path: str) -> bool:
    """A test, fixture, example, doc or lock path (roadmap HP01: those ask, never pass)."""
    segments = {part.lower() for part in path.split("/")[:-1]}
    return entropy.path_class(path) is not None or bool(segments & FIXTURE_SEGMENTS)
