"""Every rule's CWE and references are real evidence, not decoration.

A `cwe` id must be in `data/cwe.json` with a mapping-allowed usage; a `references` URL must be
https and come from a host this test explicitly trusts; `data/cwe.json` must hold nothing a rule
does not cite; a rendered refusal must carry its rule's CWE ids; and the setup contract must carry
the same cwe/references the registry does.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

import pytest
from chock_security.decision import DENY, FileText
from chock_security.engine import evaluate
from chock_security.pack import weaknesses
from chock_security.rules import registry
from gen_java_security_contract import rendered
from java_security.cases import CASES, FLOW_CASES

RULES = registry()
WEAKNESSES = weaknesses()
CONTRACT_SCRIPT = re.compile(r'<script type="application/json" id="contract">(.*?)</script>', re.S)

#: Hosts this policy actually cites evidence from. Kept tight -- add a host only when a rule
#: genuinely needs it, never to make a check pass.
TRUSTED_HOSTS = {
    "cheatsheetseries.owasp.org",
    "commons.apache.org",
    "owasp.org",
    "nvd.nist.gov",
    "docs.spring.io",
    "developer.android.com",
    "mybatis.org",
    "freemarker.apache.org",
    "logging.apache.org",
    "struts.apache.org",
}


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_carries_at_least_one_mapped_cwe(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert rule.cwe, f"{rule_id} carries no CWE"
    for cwe_id in rule.cwe:
        assert cwe_id in WEAKNESSES, f"{rule_id} cites {cwe_id}, which data/cwe.json does not carry"
        usage = WEAKNESSES[cwe_id]["usage"]
        assert usage in ("Allowed", "Allowed-with-Review"), f"{rule_id} cites {cwe_id}, mapping usage {usage!r}"


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_carries_at_least_one_verified_reference(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert rule.references, f"{rule_id} carries no reference"
    assert len(rule.references) == len(set(rule.references)), f"{rule_id} repeats a reference"
    for url in rule.references:
        parsed = urlparse(url)
        assert parsed.scheme == "https", f"{rule_id} references a non-https URL: {url}"
        assert parsed.netloc in TRUSTED_HOSTS, f"{rule_id} references an untrusted host: {url}"


def test_cwe_json_holds_nothing_no_rule_cites() -> None:
    cited = {cwe_id for rule in RULES.values() for cwe_id in rule.cwe}
    assert set(WEAKNESSES) == cited


def test_cwe_json_entries_are_verbatim_from_the_catalog() -> None:
    for cwe_id, entry in WEAKNESSES.items():
        assert entry["name"], f"{cwe_id} has no name"
        assert entry["usage"] in ("Allowed", "Allowed-with-Review")


def _no_refusing_case(rule_id: str) -> str:
    return f"{rule_id} has no refusing case in cases/"


def _a_refusing_case(rule_id: str) -> tuple[str, str]:
    for case_rule_id, path, text, lines in CASES:
        if case_rule_id == rule_id and lines:
            return path, text
    for _label, path, body, expected, _about in FLOW_CASES:
        if rule_id in expected:
            return path, body
    raise AssertionError(_no_refusing_case(rule_id))


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_a_rendered_refusal_carries_its_rules_cwe_ids(rule_id: str) -> None:
    path, text = _a_refusing_case(rule_id)
    findings = [f for f in evaluate([FileText(path, text)], {rule_id: DENY}) if f.rule_id == rule_id]
    assert findings, f"{rule_id}'s own case produced no finding for it"
    rule = RULES[rule_id]
    for finding in findings:
        assert finding.cwe == rule.cwe
        rendered_line = finding.render()
        for cwe_id in rule.cwe:
            assert cwe_id in rendered_line


def test_the_setup_contract_carries_the_registrys_cwe_and_references() -> None:
    _reference, page = rendered()

    match = CONTRACT_SCRIPT.search(page)
    assert match, "setup.html carries no #contract element"
    contract = json.loads(match.group(1).replace("<\\/", "</"))
    by_id = {r["id"]: r for r in contract["rules"]}
    assert set(by_id) == set(RULES)
    for rule_id, rule in RULES.items():
        entry = by_id[rule_id]
        assert tuple(c["id"] for c in entry["cwe"]) == rule.cwe
        assert all(c["name"] == WEAKNESSES[c["id"]]["name"] for c in entry["cwe"])
        assert tuple(entry["references"]) == rule.references
