"""iam-policy-scan: the exit codes, the findings document, the baseline, and who may waive."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from policies import gatekit, iamkit, scriptkit
from policies.iamkit import ADMIN, doc, found, repo_with, run_main

SIDECAR = ".chock/iam-policy-scan.json"
TF_WAIVED = 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["*"] # pragma: allowlist broad-privilege\n    resources = ["*"]\n  }\n}\n'
TF_PLAIN = TF_WAIVED.replace(" # pragma: allowlist broad-privilege", "")


@pytest.fixture(autouse=True)
def person(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CHOCK_AGENT_COMMIT", "CLAUDECODE", "AI_AGENT", "CHOCK_ALLOW"):
        monkeypatch.delenv(name, raising=False)


def test_clean_writes_exit_zero_with_an_empty_document(monkeypatch: pytest.MonkeyPatch) -> None:
    code, document, err = run_main(
        monkeypatch, iamkit.payload({"p.json": doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "x"})})
    )
    assert (code, document, err) == (0, {"findings": []}, "")


def test_a_block_tier_finding_exits_one_and_prints_the_document_and_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    code, document, err = run_main(monkeypatch, iamkit.payload({"p.json": doc(ADMIN)}))
    assert code == 1
    (item,) = document["findings"]
    assert item["path"] == "p.json"
    assert item["key"].startswith("iam-admin-grant|")
    assert "block; id" in item["message"]
    assert "p.json:" in err
    assert "never the agent's" not in err


def test_an_ask_tier_finding_alone_exits_three(monkeypatch: pytest.MonkeyPatch) -> None:
    ask = doc({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"})
    assert run_main(monkeypatch, iamkit.payload({"p.json": ask}))[0] == 3


def test_a_block_beside_an_ask_exits_one(monkeypatch: pytest.MonkeyPatch) -> None:
    ask = doc({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"}, ADMIN)
    assert run_main(monkeypatch, iamkit.payload({"p.json": ask}))[0] == 1


def test_in_the_agent_the_refusal_says_a_waiver_is_a_persons(monkeypatch: pytest.MonkeyPatch) -> None:
    code, _, err = run_main(monkeypatch, iamkit.payload({"p.json": doc(ADMIN)}, event="tool_use"))
    assert code == 1
    assert "never the agent's" in err


def test_a_crash_inside_the_gate_refuses_instead_of_allowing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> list:
        msg = "boom"
        raise RuntimeError(msg)

    monkeypatch.setattr(iamkit.gate, "scan_file", boom)
    code, document, err = run_main(monkeypatch, iamkit.payload({"p.json": "x"}))
    assert (code, document) == (1, None)
    assert "could not reach a decision (RuntimeError: boom)" in err


def test_a_payload_without_writes_or_with_odd_ones_judges_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_main(monkeypatch, {"event": "commit"})[0] == 0
    assert (
        run_main(
            monkeypatch, {"event": "commit", "writes": {"a.json": None, "b\\c.json": doc(ADMIN)}, "repo_root": ""}
        )[0]
        == 1
    )


def test_writes_are_judged_in_path_order_and_a_second_file_is_judged_too(monkeypatch: pytest.MonkeyPatch) -> None:
    _, document, _ = run_main(monkeypatch, iamkit.payload({"b.json": doc(ADMIN), "a.json": doc(ADMIN)}))
    assert [f["path"] for f in document["findings"]] == ["a.json", "b.json"]


def test_a_pragma_waives_a_terraform_grant_at_a_persons_commit() -> None:
    assert found({"main.tf": TF_WAIVED}) == []
    assert [f.rule for f in found({"main.tf": TF_PLAIN})] == ["iam-admin-grant"]


@pytest.mark.parametrize("event", ["commit", "push", "ci"])
def test_a_waiver_in_the_text_counts_at_every_event_a_person_reviews(event: str) -> None:
    assert found({"main.tf": TF_WAIVED}, event) == []


@pytest.mark.parametrize("event", ["tool_use", "stop", "agent-commit"])
def test_in_the_agent_a_waiver_the_agent_wrote_does_not_count(event: str, tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {})
    assert [f.rule for f in found({"main.tf": TF_WAIVED}, event, repo)] == ["iam-admin-grant"]


def test_in_the_agent_a_waiver_already_committed_on_that_exact_line_counts(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"main.tf": TF_WAIVED})
    assert found({"main.tf": TF_WAIVED + "# more\n"}, "tool_use", repo) == []
    assert found({"main.tf": TF_WAIVED}, "agent-commit", repo) == []


def test_in_the_agent_a_waiver_on_a_line_that_was_not_committed_does_not_count(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"main.tf": TF_PLAIN})
    assert [f.rule for f in found({"main.tf": TF_WAIVED}, "tool_use", repo)] == ["iam-admin-grant"]


def test_in_the_agent_a_waiver_in_a_directory_that_is_not_a_repository_does_not_count(tmp_path: Path) -> None:
    assert [f.rule for f in found({"main.tf": TF_WAIVED}, "tool_use", tmp_path)] == ["iam-admin-grant"]


def test_head_is_read_for_an_absolute_path_inside_the_repository(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"infra/main.tf": TF_WAIVED})
    assert found({str(repo / "infra" / "main.tf"): TF_WAIVED}, "tool_use", repo) == []


def test_head_is_not_read_for_an_absolute_path_outside_the_repository(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"main.tf": TF_WAIVED})
    assert [f.rule for f in found({"/elsewhere/main.tf": TF_WAIVED}, "tool_use", repo)] == ["iam-admin-grant"]


def test_a_missing_git_binary_means_no_committed_waiver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = repo_with(tmp_path, {"main.tf": TF_WAIVED})
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    assert [f.rule for f in found({"main.tf": TF_WAIVED}, "tool_use", repo)] == ["iam-admin-grant"]


YAML_GRANT = "Statement:\n  - Effect: Allow\n    Action:\n      - '*'\n    Resource: '*'\n"


@pytest.mark.parametrize(
    "text",
    [
        "Statement:\n  - Effect: Allow\n    Action:\n      - '*' # pragma: allowlist broad-privilege\n    Resource: '*'\n",
        "Statement:\n  - Effect: Allow\n    # pragma: allowlist broad-privilege\n    Action:\n      - '*'\n    Resource: '*'\n",
        "Statement:\n  - Effect: Allow\n    Action: # pragma: allowlist broad-privilege\n      - '*'\n    Resource: '*'\n",
        "Statement:\n  # pragma: allowlist broad-privilege\n  # (reviewed in TICKET-1)\n  - Effect: Allow\n    Action:\n      - '*'\n    Resource: '*'\n",
        "Statement:\n  - Effect: Allow # pragma: allowlist broad-privilege\n    Action:\n      - '*'\n    Resource: '*'\n",
    ],
)
def test_a_yaml_pragma_beside_the_grant_waives_it(text: str) -> None:
    assert found({"p.yaml": text}) == []


@pytest.mark.parametrize(
    "text",
    [
        "# pragma: allowlist broad-privilege\nOther: 1\nStatement:\n  - Effect: Allow\n    Action:\n      - '*'\n    Resource: '*'\n",
        "Statement:\n  - Effect: Allow\n    Action:\n      - '*'\n    Resource: '*'\n    # pragma: allowlist broad-privilege\n",
        "Statement:\n  - Effect: Allow\n    Action:\n      - '*'\n    Resource: '*'\n---\n# pragma: allowlist broad-privilege\n",
    ],
)
def test_a_pragma_that_is_not_beside_the_grant_or_is_not_a_comment_waives_nothing(text: str) -> None:
    assert [f.rule for f in found({"p.yaml": text})] == ["iam-admin-grant"]


def test_a_waiver_on_one_statement_does_not_waive_its_neighbour() -> None:
    text = (
        "Statement:\n  - Effect: Allow\n    Action: '*' # pragma: allowlist broad-privilege\n    Resource: '*'\n"
        "  - Effect: Allow\n    Action: '*'\n    Resource: '*'\n"
    )
    assert [f.line for f in found({"p.yaml": text})] == [6]


def sidecar(*entries: dict) -> str:
    return json.dumps({"version": 1, "waive": list(entries)})


def entry(path: str = "p.json", rule: str = "iam-admin-grant", **more: str) -> dict:
    (finding,) = found({path: doc(ADMIN)})
    return {"path": path, "rule": rule, "id": finding.sig, **more}


def test_the_sidecar_waives_a_json_statement_by_path_rule_and_id() -> None:
    assert found({"p.json": doc(ADMIN), SIDECAR: sidecar(entry(reason="break-glass"))}) == []


@pytest.mark.parametrize(
    "wrong",
    [{"path": "other.json"}, {"rule": "iam-action-wildcard"}, {"id": "000000000000"}],
)
def test_a_sidecar_entry_for_something_else_waives_nothing(wrong: dict) -> None:
    waived = {**entry(), **wrong}
    assert [f.rule for f in found({"p.json": doc(ADMIN), SIDECAR: sidecar(waived)})] == ["iam-admin-grant"]


def test_the_sidecar_counts_at_a_persons_commit_from_the_staged_blob_or_from_head(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {SIDECAR: sidecar(entry())})
    assert found({"p.json": doc(ADMIN)}, "commit", repo) == []
    assert found({"p.json": doc(ADMIN)}, "ci", repo) == []


def test_in_the_agent_only_the_sidecar_at_head_counts(tmp_path: Path) -> None:
    empty = repo_with(tmp_path, {})
    assert [f.rule for f in found({"p.json": doc(ADMIN), SIDECAR: sidecar(entry())}, "tool_use", empty)] == [
        "iam-admin-grant"
    ]


def test_in_the_agent_a_sidecar_waiver_committed_by_a_person_counts(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {SIDECAR: sidecar(entry())})
    assert found({"p.json": doc(ADMIN)}, "tool_use", repo) == []


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "[]",
        '{"version": 2, "waive": []}',
        '{"version": 1, "waive": [], "extra": 1}',
        '{"version": 1, "waive": {}}',
        '{"version": 1, "waive": ["x"]}',
        '{"version": 1, "waive": [{"path": "a", "rule": "b"}]}',
        '{"version": 1, "waive": [{"path": "a", "rule": "b", "id": "c", "all": true}]}',
        '{"version": 1, "waive": [{"path": "a", "rule": "b", "id": 5}]}',
        '{"version": 1, "waive": [{"path": "a", "rule": "", "id": "c"}]}',
    ],
)
def test_a_sidecar_that_is_not_understood_refuses_everything(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    code, document, err = run_main(monkeypatch, iamkit.payload({"p.json": doc(ADMIN), SIDECAR: bad}))
    assert (code, document) == (1, None)
    assert SIDECAR in err


def test_a_sidecar_with_no_waive_list_waives_nothing() -> None:
    assert [f.rule for f in found({"p.json": doc(ADMIN), SIDECAR: '{"version": 1}'})] == ["iam-admin-grant"]


def engine(
    tmp_path: Path, head: dict[str, str], writes: dict[str, str], event: str = gatekit.COMMIT
) -> tuple[int, str]:
    """The compiled gate through chock's own runner: the baseline run, the engine's keys and its exit codes."""
    repo = scriptkit.init_repo(tmp_path / "r", head or {"README.txt": "base\n"})
    if event == gatekit.COMMIT:
        scriptkit.write(repo, writes)
        scriptkit.git(repo, "add", "-A")
        return gatekit.judge("iam-policy-scan", repo, event)
    return gatekit.judge("iam-policy-scan", repo, event, writes, writes)


def test_through_the_engine_an_old_grant_the_change_leaves_alone_does_not_block(tmp_path: Path) -> None:
    old = {"p.json": doc(ADMIN)}
    scoped = {"Effect": "Allow", "Action": "s3:Get*", "Resource": "x"}
    assert engine(tmp_path, old, {"p.json": doc(ADMIN, scoped)})[0] == 0


def test_through_the_engine_a_moved_grant_is_old_and_a_twin_is_new(tmp_path: Path) -> None:
    scoped = {"Effect": "Allow", "Action": "s3:Get*", "Resource": "x"}
    old = {"p.json": doc(ADMIN, scoped)}
    assert engine(tmp_path, old, {"p.json": doc(scoped, ADMIN)})[0] == 0
    assert engine(tmp_path / "t", old, {"p.json": doc(ADMIN, ADMIN, scoped)})[0] == 1


def test_through_the_engine_a_new_file_with_a_grant_blocks_and_names_it(tmp_path: Path) -> None:
    code, said = engine(tmp_path, {}, {"p.json": doc(ADMIN)})
    assert code == 1
    assert "p.json" in said
    assert "iam-admin-grant" in said


def test_through_the_engine_an_ask_is_refused_at_commit_until_a_person_answers(tmp_path: Path) -> None:
    ask = doc({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"})
    code, said = engine(tmp_path, {}, {"p.json": ask})
    assert code == 1
    assert "asks a person" in said


def test_through_the_engine_the_agent_is_refused_a_wildcard_it_writes(tmp_path: Path) -> None:
    code, _ = engine(tmp_path, {}, {"main.tf": TF_WAIVED}, gatekit.PRE_TOOL_USE)
    assert code == 1


def test_through_the_engine_removing_a_waiver_makes_the_grant_new(tmp_path: Path) -> None:
    assert engine(tmp_path, {"main.tf": TF_WAIVED}, {"main.tf": TF_PLAIN})[0] == 1
    assert engine(tmp_path / "t", {"main.tf": TF_PLAIN}, {"main.tf": TF_WAIVED})[0] == 0


def test_run_as_a_script_it_reads_the_payload_on_stdin_and_exits_with_its_verdict(tmp_path: Path) -> None:
    script = iamkit.IMPL / "iam-policy-scan-gate.py"
    run = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(iamkit.payload({"p.json": doc(ADMIN)}, root=tmp_path)),
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 1
    assert json.loads(run.stdout)["findings"]
