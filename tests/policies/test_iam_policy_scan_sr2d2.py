"""iam-policy-scan: template files judged by path, and sidecar waivers counted against HEAD's copy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies.iamkit import ADMIN, doc, found, repo_with, rules

BLOCK = "block"
SIDECAR = ".chock/iam-policy-scan.json"
EXPLICIT_KEY = "  labels:\n    ? app\n    : ops\n"
ROLE = (
    "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: ops\n"
    + EXPLICIT_KEY
    + "rules:\n- apiGroups:\n  - '*'\n  resources:\n  - '*'\n  verbs:\n  - '*'\n"
)


def test_a_marker_in_a_comment_does_not_make_an_unreadable_file_a_template() -> None:
    assert rules("k8s/clusterrole.yaml", "# {{ rendered in CI }}\n" + ROLE) == [("iam-unreadable", BLOCK)]


def test_a_marker_in_a_comment_does_not_hide_the_file_outside_a_template_directory() -> None:
    assert rules("deploy/role.yml", "# {% note %}\n" + ROLE) == [("iam-unreadable", BLOCK)]


def test_a_template_path_that_still_does_not_read_after_its_directives_are_set_aside_is_refused() -> None:
    assert rules("chart/templates/role.yaml", "# {{ x }}\n" + ROLE) == [("iam-unreadable", BLOCK)]


def test_an_unclosed_multi_line_directive_in_a_template_is_refused() -> None:
    text = "{{- /*\nnote\n*/ -}}\n" + ROLE
    assert rules("chart/templates/role.yaml", text) == [("iam-unreadable", BLOCK)]


def test_a_template_directory_file_with_directives_is_still_read() -> None:
    text = "kind: Role\nrules:\n{{- if .Values.rbac }}\n  - resources: ['*']\n    verbs: [get]\n{{- end }}\n"
    assert rules("chart/templates/role.yaml", text) == [("k8s-rbac-wildcard", BLOCK)]


def test_a_template_that_is_still_not_yaml_is_refused() -> None:
    text = "kind: Role\nrules:\n  - resources: ['*']\n    verbs: {{ .Values.verbs | toJson }}: [\n"
    assert rules("chart/templates/role.yaml", text) == [("iam-unreadable", BLOCK)]


def sidecar_for(path: str) -> str:
    (finding,) = found({path: doc(ADMIN)})
    return json.dumps({"version": 1, "waive": [{"path": path, "rule": "iam-admin-grant", "id": finding.sig}]})


def two_roles(copies: int) -> str:
    statements = [ADMIN] * copies
    return doc(*statements)


def test_in_the_agent_a_waived_grant_is_excused_once_per_copy_at_head(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {SIDECAR: sidecar_for("t.json"), "t.json": two_roles(1)})
    assert found({"t.json": two_roles(1)}, "tool_use", repo) == []
    assert [f.rule for f in found({"t.json": two_roles(2)}, "tool_use", repo)] == ["iam-admin-grant"]


def test_in_the_agent_a_waived_grant_in_a_new_file_is_excused_once(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {SIDECAR: sidecar_for("t.json")})
    assert found({"t.json": two_roles(1)}, "tool_use", repo) == []
    assert [f.rule for f in found({"t.json": two_roles(3)}, "tool_use", repo)] == ["iam-admin-grant"] * 2


@pytest.mark.parametrize("event", ["commit", "ci"])
def test_a_persons_commit_still_trusts_the_waiver(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {SIDECAR: sidecar_for("t.json"), "t.json": two_roles(1)})
    assert found({"t.json": two_roles(2)}, event, repo) == []
