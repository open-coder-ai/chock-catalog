"""The guided page and its reference file describe exactly the packs and rules the gate runs."""

from __future__ import annotations

import json
import re

from chock_security.decision import DENY
from chock_security.rules import packs, registry
from gen_java_security_contract import rendered
from java_security.conftest import SETUP

EMBEDDED = re.compile(r'<script type="application/json" id="contract">(.*?)</script>', re.S)


def _embedded() -> dict:
    match = EMBEDDED.search((SETUP / "setup.html").read_text(encoding="utf-8"))
    assert match, "setup.html carries no #contract element"
    return json.loads(match.group(1).replace("<\\/", "</"))


def test_the_committed_page_and_reference_are_what_the_generator_renders() -> None:
    reference, page = rendered()
    assert (SETUP / "references" / "setup-contract.json").read_text(encoding="utf-8") == reference
    assert (SETUP / "setup.html").read_text(encoding="utf-8") == page


def test_the_page_lists_every_pack_and_rule_the_gate_runs() -> None:
    contract = _embedded()
    assert [p["id"] for p in contract["packs"]] == list(packs())
    assert [r["id"] for r in contract["rules"]] == list(registry())


def test_the_page_defaults_to_deny_and_claims_no_agent() -> None:
    contract = _embedded()
    assert contract["default"] == DENY
    assert contract["agent"] is None
