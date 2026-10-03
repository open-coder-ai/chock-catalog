"""iam-policy-scan: Kubernetes RBAC objects and Azure Owner or Contributor at subscription scope."""

from __future__ import annotations

import json

import pytest
from policies.iamkit import found, rules

BLOCK, ASK = "block", "ask"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"


def role(kind: str, rule: str) -> str:
    return f"apiVersion: rbac.authorization.k8s.io/v1\nkind: {kind}\nmetadata:\n  name: r\nrules:\n{rule}"


def binding(kind: str, name: str, ref_kind: str = "ClusterRole") -> str:
    return f"kind: {kind}\nmetadata:\n  name: b\nroleRef:\n  kind: {ref_kind}\n  name: {name}\nsubjects:\n  - kind: User\n    name: x\n"


K8S_CASES = {
    "verbs-multiline": (
        role("Role", "  - apiGroups: ['']\n    resources: [pods]\n    verbs:\n      - '*'\n"),
        [("k8s-rbac-wildcard", BLOCK)],
    ),
    "resources-star": (
        role("ClusterRole", "  - apiGroups: ['']\n    resources: ['*']\n    verbs: [get]\n"),
        [("k8s-rbac-wildcard", BLOCK)],
    ),
    "api-groups-star-only": (
        role("ClusterRole", "  - apiGroups: ['*']\n    resources: [pods]\n    verbs: [get]\n"),
        [("k8s-rbac-wildcard", ASK)],
    ),
    "second-rule": (
        role(
            "Role",
            "  - apiGroups: ['']\n    resources: [pods]\n    verbs: [get]\n  - apiGroups: ['']\n    resources: [secrets]\n    verbs: ['*']\n",
        ),
        [("k8s-rbac-wildcard", BLOCK)],
    ),
    "kind-case": (role("clusterrole", "  - resources: ['*']\n    verbs: [get]\n"), [("k8s-rbac-wildcard", BLOCK)]),
    "cluster-admin": (binding("ClusterRoleBinding", "cluster-admin"), [("k8s-cluster-admin-binding", BLOCK)]),
    "cluster-admin-case": (binding("ClusterRoleBinding", "Cluster-Admin"), [("k8s-cluster-admin-binding", BLOCK)]),
    "role-binding-cluster-admin": (binding("RoleBinding", "cluster-admin"), [("k8s-cluster-admin-binding", ASK)]),
    "in-a-list": (
        "kind: List\nitems:\n  - kind: ClusterRoleBinding\n    roleRef:\n      name: cluster-admin\n",
        [("k8s-cluster-admin-binding", BLOCK)],
    ),
    "named": (role("Role", "  - apiGroups: ['']\n    resources: [pods]\n    verbs: [get, list]\n"), []),
    "binding-to-edit": (binding("ClusterRoleBinding", "edit"), []),
    "binding-without-roleref": ("kind: ClusterRoleBinding\nmetadata:\n  name: b\n", []),
    "binding-with-odd-roleref": ("kind: ClusterRoleBinding\nroleRef: cluster-admin\n", []),
    "role-with-odd-rules": ("kind: Role\nrules: 5\n", []),
    "role-with-odd-rule-entries": ("kind: Role\nrules:\n  - just text\n", []),
    "other-kind": ("kind: ConfigMap\ndata:\n  verbs: '*'\n", []),
    "no-kind": ("rules:\n  - verbs: ['*']\n", []),
}


@pytest.mark.parametrize("case", sorted(K8S_CASES))
def test_kubernetes_object_is_judged(case: str) -> None:
    text, expected = K8S_CASES[case]
    assert rules("rbac.yaml", text) == expected


def test_a_json_manifest_is_judged_the_same() -> None:
    manifest = {"kind": "ClusterRoleBinding", "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}
    assert rules("crb.json", json.dumps(manifest)) == [("k8s-cluster-admin-binding", BLOCK)]


def test_a_wildcard_rule_is_reported_at_its_verbs_and_its_binding_at_its_role() -> None:
    text = role("Role", "  - apiGroups: ['']\n    resources: [pods]\n    verbs:\n      - '*'\n")
    assert [f.line for f in found({"r.yaml": text})] == [9]
    assert [f.line for f in found({"b.yaml": binding("ClusterRoleBinding", "cluster-admin")})] == [5]


def test_a_second_identical_rule_is_a_second_finding_with_one_id() -> None:
    rule = "  - resources: ['*']\n    verbs: [get]\n"
    twice = found({"r.yaml": role("Role", rule + rule)})
    assert len(twice) == 2
    assert twice[0].key == twice[1].key


def test_helm_directives_are_set_aside_before_the_yaml_is_read() -> None:
    text = "kind: ClusterRole\nmetadata:\n  name: {{ .Release.Name }}\nrules:\n{{- if .Values.rbac }}\n  - resources: ['*']\n    verbs: [get]\n{{- end }}\n"
    assert rules("templates/role.yaml", text) == [("k8s-rbac-wildcard", BLOCK)]


def test_jinja_blocks_are_set_aside_too() -> None:
    text = "kind: Role\nrules:\n{% if x %}\n  - resources: ['*']\n    verbs: [get]\n{% endif %}\n"
    assert rules("role.yml", text) == [("k8s-rbac-wildcard", BLOCK)]


def test_a_template_that_is_still_not_yaml_is_not_judged() -> None:
    text = "kind: Role\nrules:\n  - resources: ['*']\n    verbs: {{ .Values.verbs | toJson }}: [\n"
    assert rules("role.yaml", text) == []


def test_a_yaml_manifest_that_cannot_be_read_and_is_not_a_template_is_refused() -> None:
    text = "kind: Role\nrules:\n  - resources: ['*']\n    verbs: [a: b]\n"
    assert rules("role.yaml", text) == [("iam-unreadable", BLOCK)]


def arm(role_id: str, **where: object) -> str:
    resource = {"type": "Microsoft.Authorization/roleAssignments", "properties": {"roleDefinitionId": role_id, **where}}
    return json.dumps(
        {
            "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
            "resources": [resource],
        }
    )


def rg_arm(role_id: str, **where: object) -> str:
    resource = {"type": "Microsoft.Authorization/roleAssignments", "properties": {"roleDefinitionId": role_id, **where}}
    return json.dumps(
        {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "resources": [resource],
        }
    )


ROLE_ID = "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{}')]"
ARM_CASES = {
    "owner-in-subscription-deployment": (arm(ROLE_ID.format(OWNER)), [("azure-subscription-owner", BLOCK)]),
    "contributor": (arm(ROLE_ID.format(CONTRIBUTOR)), [("azure-subscription-owner", BLOCK)]),
    "owner-by-full-id": (
        arm(f"/providers/Microsoft.Authorization/roleDefinitions/{OWNER.upper()}"),
        [("azure-subscription-owner", BLOCK)],
    ),
    "explicit-subscription-scope": (
        rg_arm(ROLE_ID.format(OWNER), scope="/subscriptions/0000-1111"),
        [("azure-subscription-owner", BLOCK)],
    ),
    "scope-function": (
        rg_arm(ROLE_ID.format(OWNER), scope="[subscription().id]"),
        [("azure-subscription-owner", BLOCK)],
    ),
    "resource-group-deployment": (rg_arm(ROLE_ID.format(OWNER)), []),
    "resource-group-scope-in-subscription-deployment": (
        arm(ROLE_ID.format(OWNER), scope="/subscriptions/0000/resourceGroups/rg"),
        [],
    ),
    "reader": (arm(ROLE_ID.format(READER)), []),
    "other-resource": (
        json.dumps(
            {"resources": [{"type": "Microsoft.Storage/storageAccounts", "properties": {"roleDefinitionId": OWNER}}]}
        ),
        [],
    ),
    "schema-not-a-string": (
        json.dumps(
            {
                "$schema": 5,
                "resources": [
                    {"type": "Microsoft.Authorization/roleAssignments", "properties": {"roleDefinitionId": OWNER}}
                ],
            }
        ),
        [],
    ),
    "root-is-a-list": (
        json.dumps(
            [
                {
                    "type": "Microsoft.Authorization/roleAssignments",
                    "properties": {"roleDefinitionId": OWNER, "scope": "[subscription().id]"},
                }
            ]
        ),
        [("azure-subscription-owner", BLOCK)],
    ),
}


@pytest.mark.parametrize("case", sorted(ARM_CASES))
def test_arm_role_assignment_is_judged(case: str) -> None:
    text, expected = ARM_CASES[case]
    assert rules("assign.json", text) == expected


def test_arm_json_with_comments_is_read() -> None:
    assert rules("assign.json", "// at subscription scope\n" + arm(ROLE_ID.format(OWNER))) == [
        ("azure-subscription-owner", BLOCK)
    ]


def assignment(**attrs: str) -> str:
    body = "".join(f"  {k} = {v}\n" for k, v in attrs.items())
    return f'resource "azurerm_role_assignment" "a" {{\n{body}}}\n'


TF_CASES = {
    "owner-literal-subscription": (
        assignment(scope='"/subscriptions/0000-1111"', role_definition_name='"Owner"'),
        [("azure-subscription-owner", BLOCK)],
    ),
    "contributor-lower": (
        assignment(scope='"/subscriptions/0000"', role_definition_name='"contributor"'),
        [("azure-subscription-owner", BLOCK)],
    ),
    "owner-by-id": (
        assignment(scope='"/subscriptions/0000"', role_definition_id=f'"/providers/x/{OWNER}"'),
        [("azure-subscription-owner", BLOCK)],
    ),
    "subscription-data-source": (
        assignment(scope="data.azurerm_subscription.current.id", role_definition_name='"Owner"'),
        [("azure-subscription-owner", BLOCK)],
    ),
    "interpolated-subscription": (
        assignment(
            scope='"/subscriptions/${data.azurerm_client_config.current.subscription_id}"',
            role_definition_name='"Owner"',
        ),
        [("azure-subscription-owner", BLOCK)],
    ),
    "subscription-function": (
        assignment(scope="subscription().id", role_definition_name='"Owner"'),
        [("azure-subscription-owner", BLOCK)],
    ),
    "resource-group-scope": (
        assignment(scope='"/subscriptions/0000/resourceGroups/rg"', role_definition_name='"Owner"'),
        [],
    ),
    "resource-scope": (assignment(scope="azurerm_storage_account.s.id", role_definition_name='"Owner"'), []),
    "reader": (assignment(scope='"/subscriptions/0000"', role_definition_name='"Reader"'), []),
    "no-scope": (assignment(role_definition_name='"Owner"'), []),
    "computed-role-name": (assignment(scope='"/subscriptions/0000"', role_definition_name="var.role"), []),
    "role-name-and-no-id": (assignment(scope='"/subscriptions/0000"'), []),
}


@pytest.mark.parametrize("case", sorted(TF_CASES))
def test_terraform_role_assignment_is_judged(case: str) -> None:
    text, expected = TF_CASES[case]
    assert rules("rbac.tf", text) == expected


BICEP_HEAD = "resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n  name: guid('x')\n"
BICEP_BODY = "  properties: {\n    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '%s')\n  }\n}\n"
BICEP_CASES = {
    "target-scope-subscription": (
        "targetScope = 'subscription'\n\n" + BICEP_HEAD + BICEP_BODY % OWNER,
        [("azure-subscription-owner", BLOCK)],
    ),
    "contributor": (
        "targetScope = 'subscription'\n" + BICEP_HEAD + BICEP_BODY % CONTRIBUTOR,
        [("azure-subscription-owner", BLOCK)],
    ),
    "scope-subscription-function": (
        BICEP_HEAD + "  scope: subscription()\n" + BICEP_BODY % OWNER,
        [("azure-subscription-owner", BLOCK)],
    ),
    "scope-resource-group": (
        "targetScope = 'subscription'\n" + BICEP_HEAD + "  scope: resourceGroup('rg')\n" + BICEP_BODY % OWNER,
        [],
    ),
    "no-target-scope": (BICEP_HEAD + BICEP_BODY % OWNER, []),
    "reader": ("targetScope = 'subscription'\n" + BICEP_HEAD + BICEP_BODY % READER, []),
    "two-assignments": (
        "targetScope = 'subscription'\n"
        + BICEP_HEAD
        + BICEP_BODY % OWNER
        + BICEP_HEAD.replace(" ra ", " rb ")
        + BICEP_BODY % CONTRIBUTOR,
        [("azure-subscription-owner", BLOCK)] * 2,
    ),
    "braces-and-strings-in-the-body": (
        "targetScope = 'subscription'\n"
        + BICEP_HEAD
        + "  // a } in a comment\n  tags: { a: '}' }\n"
        + BICEP_BODY % OWNER,
        [("azure-subscription-owner", BLOCK)],
    ),
    "unterminated": (
        "targetScope = 'subscription'\n" + BICEP_HEAD + "  properties: {\n    roleDefinitionId: '" + OWNER + "'\n",
        [("azure-subscription-owner", BLOCK)],
    ),
}


@pytest.mark.parametrize("case", sorted(BICEP_CASES))
def test_bicep_role_assignment_is_judged(case: str) -> None:
    text, expected = BICEP_CASES[case]
    assert rules("main.bicep", text) == expected


def test_a_bicep_finding_is_reported_at_its_resource() -> None:
    text = "targetScope = 'subscription'\n\n" + BICEP_HEAD + BICEP_BODY % OWNER
    assert [f.line for f in found({"main.bicep": text})] == [3]
