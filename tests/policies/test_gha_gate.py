"""ci-github-actions-security: the gate script's contract (scope, keys, waivers, exit codes, refusals) and the tree."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest
import yaml
from policies import scriptkit
from policies.ghakit import GATE, POLICY, TABLES, found, gate, rules, tree, workflow

INJECT = workflow(
    "  issues:", "      - run: echo ${{ github.event.issue.title }}  # chock: allow gha-template-injection\n"
)


@pytest.mark.parametrize(
    ("path", "judged"),
    [
        (".github/workflows/ci.yml", True),
        (".github/workflows/ci.YAML", True),
        ("sub/.github/workflows/ci.yml", True),
        (".github\\workflows\\ci.yml", True),
        (".github/workflows/nested/ci.yml", False),
        ("tools/x/action.yml", True),
        (".github/dependabot.yaml", True),
        ("docs/ci.yml", False),
    ],
)
def test_scope(path: str, judged: bool) -> None:
    text = "version: 2\nupdates:\n  - package-ecosystem: npm\n" if "dependabot" in path else INJECT
    if "action" in path:
        text = "runs:\n  using: composite\n  steps:\n    - run: echo ${{ inputs.x }}\n"
    assert bool(found(text, path)) is judged


def test_non_text_write_is_skipped() -> None:
    assert gate.findings({"event": "tool_use", "writes": {".github/workflows/a.yml": None}}, TABLES) == []


def test_waiver_counts_only_at_a_persons_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHOCK_AGENT_COMMIT", raising=False)
    assert not found(INJECT, event="commit")
    assert found(INJECT, event="tool_use")
    assert found(INJECT, event="agent-commit")
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", "1")
    assert found(INJECT, event="commit")


def test_waiver_names_the_rule() -> None:
    other = INJECT.replace("gha-template-injection", "gha-secret-echo")
    assert found(other, event="commit")


def test_unreadable_files_are_one_finding_keyed_by_reason() -> None:
    hit = found("on: push\njobs:\n\tbuild: {}\n")
    assert [h["rule"] for h in hit] == ["gha-unreadable"]
    assert hit[0]["line"] == 3
    assert hit[0]["key"].startswith("gha-unreadable|file|")
    assert [h["rule"] for h in found("a: &x 1\nb: *y\n")] == ["gha-unreadable"]


def test_alias_expansion_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tree, "MAX_EXPANDED", 10)
    text = "a: &a [1, 2, 3, 4]\nb: [*a, *a, *a]\n"
    assert [h["rule"] for h in found(text)] == ["gha-unreadable"]


def test_multi_document_files_judge_every_document() -> None:
    text = "on: push\npermissions: {}\njobs: {}\n---\non: pull_request_target\npermissions: {}\njobs: {}\n"
    assert [h["rule"] for h in found(text)] == ["gha-dangerous-trigger"]


def test_keys_ignore_line_numbers_and_count_copies() -> None:
    a = found(INJECT)
    b = found("\n\n" + INJECT)
    assert [f["key"] for f in a] == [f["key"] for f in b]
    assert a[0]["line"] + 2 == b[0]["line"]


def test_tree_lookups() -> None:
    (doc,) = tree.documents("a:\n  b: [1, 2]\nc: x\nc: y\n")
    assert doc.value(("a",)) is None
    assert doc.text(("c",)) == "y"
    assert doc.text(("missing",)) is None
    assert doc.line(("a", "b", 9, "z")) == 2
    assert doc.line(("nope",)) == 1
    assert doc.keys(("a", "b")) == [0, 1]
    assert [n.value for n in doc.under(("a",))] == ["1", "2"]
    (merged,) = tree.documents("x: &x {k: 1}\ny:\n  <<: [*x]\n")
    assert merged.value(("y", "k")) is None
    assert [n.merged for n in merged.values(("y", "k"))] == [True]
    assert merged.has(("y", "k")) and not merged.has(("y", "k"), trusted=True)


def test_first_line_falls_back_when_the_text_is_split() -> None:
    text = workflow("  issues:", '      - run: "echo ${{ github.event.issue.\\x74itle }}"\n')
    assert [h["line"] for h in found(text)] == [8]


def _run(stdin: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = gate.main()
    out, err = capsys.readouterr()
    return code, json.loads(out) if out else {}, err


def test_exit_codes(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    payload = {"event": "tool_use", "writes": {".github/workflows/a.yml": INJECT}}
    code, doc, err = _run(json.dumps(payload), monkeypatch, capsys)
    assert code == 1
    assert doc["findings"][0]["rule"] == "gha-template-injection"
    assert "chock: allow <rule id>" in err
    ask = {"event": "tool_use", "writes": {".github/workflows/a.yml": "on: workflow_run\npermissions: {}\njobs: {}\n"}}
    assert _run(json.dumps(ask), monkeypatch, capsys)[0] == 3
    clean = {"event": "tool_use", "writes": {".github/workflows/a.yml": "on: push\npermissions: {}\njobs: {}\n"}}
    assert _run(json.dumps(clean), monkeypatch, capsys)[:2] == (0, {"findings": []})
    code, _, err = _run("not json", monkeypatch, capsys)
    assert code == 2
    assert "cannot judge" in err


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(kind="ioc"),
        lambda d: d.update(agent_actions=["Upper/Case"]),
        lambda d: d.update(cloud_key_inputs={"a/b": "x"}),
    ],
)
def test_a_broken_table_is_refused(
    change: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = json.loads(gate.TABLE.read_text(encoding="utf-8"))
    change(doc)  # type: ignore[operator]
    table = tmp_path / "data" / "actions.json"
    table.parent.mkdir()
    table.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setattr(gate, "TABLE", table)
    code, _, err = _run(json.dumps({"event": "tool_use", "writes": {}}), monkeypatch, capsys)
    assert code == 2
    assert "actions.json" in err


def test_runs_as_a_process(tmp_path: Path) -> None:
    payload = json.dumps({"event": "commit", "writes": {".github/workflows/a.yml": INJECT.replace("# chock", "# no")}})
    proc = scriptkit.run_script_full(POLICY, GATE, tmp_path, payload)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["findings"][0]["key"] == "gha-template-injection|build|github.event.issue.title"


def test_every_rule_in_the_table_is_produced_by_a_check() -> None:
    assert rules.RULES["gha-unreadable"].tier == rules.BLOCK
    assert {r.pack for r in rules.RULES.values()} == {
        "injection", "triggers", "permissions", "agents", "secrets", "supply", "hygiene",
    }  # fmt: skip
    assert all(r.cwe.startswith("CWE-") and r.cicd.startswith("CICD-SEC-") for r in rules.RULES.values())


SUITE = yaml.safe_load((scriptkit.ROOT / "base" / POLICY / "evals" / "suite.yaml").read_text(encoding="utf-8"))
NAMED = re.compile(r"\((gha-[a-z-]+)")


@pytest.mark.parametrize("case", SUITE["suite"]["cases"], ids=lambda c: c["id"])
def test_each_eval_warns_for_the_rule_it_names(case: dict) -> None:
    """A warn case must warn for its own reason, never because the fixture failed to parse."""
    run = case["execute"]
    writes = run.get("files") or run.get("writes")
    rules_hit = {f["rule"] for f in gate.findings({"event": "tool_use", "writes": writes}, TABLES)}
    named = set(NAMED.findall(case["expect"]))
    assert named <= rules_hit, (named, rules_hit)
    if "gha-unreadable" not in named:
        assert "gha-unreadable" not in rules_hit
