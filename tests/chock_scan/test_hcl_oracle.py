"""chock_scan.hcl and hcl_json held to hashicorp/hcl's own answers (oracle/*.json, recorded by oracle/main.go).

Where HCL refuses a case the scanner must raise HclError. Where HCL reads it, the scanner must give the
same blocks (type, labels, order) and attributes, and every literal it reports must equal HCL's value; a
value it reports as COMPUTED (wholly or in part) is conservative and matches anything. JSON cases read
only the block types and argument names the case lists, as Terraform reads a body against its schema.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

ORACLE = Path(__file__).parent / "oracle"
NATIVE = json.loads((ORACLE / "native.json").read_text(encoding="utf-8"))
JSON = json.loads((ORACLE / "json.json").read_text(encoding="utf-8"))
#: HCL refuses these and the scanner reads them: each only ever over-reports, never hides.
LENIENT: set[str] = set()


def lines(m: SimpleNamespace, block: object, case: dict, path: str = "") -> list[str]:
    """The scanner's reading in the oracle's line format: one line per attribute (sorted) and block.

    A JSON case (one with "attrs") keeps only its listed arguments and nested block types.
    """
    names = case.get("attrs")
    nested = None if names is None else case.get("nested", {})
    out = []
    for attr in sorted(block.attributes, key=lambda a: a.key):
        if names is None or attr.key in names:
            out.append(f"{path}|A|{attr.key}|" + ("C" if m.hcl.is_computed(attr.value) else _json(attr.value)))
    children = [b for b in block.blocks if nested is None or path == "" or b.type in nested]
    for i, child in enumerate(children):
        here = f"{path}/{i}:{child.type}{json.dumps(list(child.labels), separators=(',', ':'), ensure_ascii=False)}"
        out.append(here + "|B")
        out += lines(m, child, case, here)
    return out


def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def split(line: str) -> tuple[str, object]:
    """(everything but the value, the value: parsed JSON, or "C"); a block line has no value."""
    if "|A|" not in line:
        return line, None
    path, rest = line.split("|A|", 1)
    key, value = rest.split("|", 1)
    return f"{path}|A|{key}", value if value == "C" else json.loads(value)


def agrees(ours: list[str], theirs: list[str]) -> bool:
    """Same lines in the same order; a literal of ours equals HCL's value; our COMPUTED matches any."""
    if len(ours) != len(theirs):
        return False
    for mine, hcl in zip(ours, theirs, strict=True):
        (head, value), (their_head, their_value) = split(mine), split(hcl)
        if head != their_head or value not in ("C", their_value):
            return False
    return True


@pytest.mark.parametrize("case", NATIVE, ids=[c["name"] for c in NATIVE])
def test_native_syntax_reads_as_hcl_reads_it(m: SimpleNamespace, case: dict) -> None:
    _check(m, case, m.hcl.parse)


@pytest.mark.parametrize("case", JSON, ids=[c["name"] for c in JSON])
def test_json_syntax_reads_as_hcl_reads_it(m: SimpleNamespace, case: dict) -> None:
    _check(m, case, m.hcl_json.parse_json)


def _check(m: SimpleNamespace, case: dict, parse: Callable[[str], object]) -> None:
    if case["hcl"] == "ERR" and case["name"] not in LENIENT:
        with pytest.raises(m.hcl.HclError):
            parse(case["src"])
        return
    ours = lines(m, parse(case["src"]), case)
    assert agrees(ours, case["hcl"]), (ours, case["hcl"])


def test_the_oracle_covers_both_answers() -> None:
    for cases in (NATIVE, JSON):
        assert any(c["hcl"] == "ERR" for c in cases)
        assert sum(c["hcl"] != "ERR" for c in cases) > 20
        assert len({c["name"] for c in cases}) == len(cases)
