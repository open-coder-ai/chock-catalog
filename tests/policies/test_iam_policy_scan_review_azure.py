"""iam-policy-scan: Azure scope and role forms the adversarial review found."""

from __future__ import annotations

import json

import pytest
from policies.iamkit import found, rules

BLOCK = "block"
OWNER_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
ARM_ROLE = f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{OWNER_ID}')]"
OWNER_PROP = f"  properties: {{ roleDefinitionId: '{OWNER_ID}' }}\n"
BICEP_HEAD = "resource a 'Microsoft.Authorization/roleAssignments@2022-04-01' "


def assignment(scope: str) -> str:
    return f'resource "azurerm_role_assignment" "a" {{\n  scope = {scope}\n  role_definition_name = "Owner"\n}}\n'


@pytest.mark.parametrize(
    "scope",
    [
        '"${data.azurerm_subscription.primary.id}"',
        '"/providers/Microsoft.Management/managementGroups/root"',
        '"/"',
        '"/subscriptions/${var.a}${var.b}"',
        '"/subscriptions/${lookup(var.m, "k", {})}"',
        "data.azurerm_management_group.m.id",
        "data.azurerm_subscription.primary[0].id",
        'format("/subscriptions/%s", var.s)',
    ],
)
def test_terraform_scopes_at_or_above_a_subscription_in_any_spelling(scope: str) -> None:
    assert rules("m.tf", assignment(scope)) == [("azure-subscription-owner", BLOCK)]


def test_a_resource_group_scope_with_templates_is_still_not_subscription_scope() -> None:
    assert rules("m.tf", assignment('"/subscriptions/${var.s}/resourceGroups/${var.rg}"')) == []


@pytest.mark.parametrize(
    "scope",
    [
        "[managementGroup().id]",
        "[tenantResourceId('Microsoft.Management/managementGroups','m')]",
        "[concat('/subscriptions/', parameters('s'))]",
    ],
)
def test_arm_scopes_at_or_above_a_subscription(scope: str) -> None:
    resource = {
        "type": "Microsoft.Authorization/roleAssignments",
        "scope": scope,
        "properties": {"roleDefinitionId": ARM_ROLE},
    }
    assert rules("a.json", json.dumps({"resources": [resource]})) == [("azure-subscription-owner", BLOCK)]


@pytest.mark.parametrize("schema", ["managementGroupDeploymentTemplate.json", "tenantDeploymentTemplate.json"])
def test_arm_deployments_above_a_subscription_with_no_scope(schema: str) -> None:
    resource = {"type": "Microsoft.Authorization/roleAssignments", "properties": {"roleDefinitionId": ARM_ROLE}}
    text = json.dumps({"$Schema": "https://x/2019-08-01/" + schema + "#", "resources": [resource]})
    assert rules("a.json", text) == [("azure-subscription-owner", BLOCK)]


@pytest.mark.parametrize(
    "header",
    ["= [for p in ps: if (p.x) {", "= [\n  for p in ps: {", "= if (\n  a &&\n  b\n) {"],
)
def test_more_bicep_header_shapes(header: str) -> None:
    text = "targetScope = 'subscription'\n" + BICEP_HEAD + header + "\n" + OWNER_PROP + "}\n"
    assert rules("m.bicep", text) == [("azure-subscription-owner", BLOCK)]


@pytest.mark.parametrize("scope_line", ["  scope: managementGroup('x')\n", "  scope: tenant()\n"])
def test_bicep_scope_at_a_management_group_or_tenant(scope_line: str) -> None:
    text = BICEP_HEAD + "= {\n" + scope_line + OWNER_PROP + "}\n"
    assert rules("m.bicep", text) == [("azure-subscription-owner", BLOCK)]


def test_bicep_target_scope_above_a_subscription_with_no_scope() -> None:
    text = "targetScope = 'managementGroup'\n" + BICEP_HEAD + "= {\n" + OWNER_PROP + "}\n"
    assert rules("m.bicep", text) == [("azure-subscription-owner", BLOCK)]


@pytest.mark.parametrize(
    "decoy",
    [
        "  /* \n  scope: resourceGroup('rg')\n  */\n",
        "  tags: {\n    scope: 'x'\n  }\n",
        "  note: '''\n  scope: rg\n  '''\n",
    ],
)
def test_a_bicep_scope_in_a_comment_a_string_or_a_nested_object_is_not_the_resources_scope(decoy: str) -> None:
    text = "targetScope = 'subscription'\n" + BICEP_HEAD + "= {\n" + decoy + OWNER_PROP + "}\n"
    assert rules("m.bicep", text) == [("azure-subscription-owner", BLOCK)]


def test_a_bicep_resource_with_no_body_is_ignored() -> None:
    assert rules("m.bicep", BICEP_HEAD + "=\n") == []


def test_many_unbalanced_bicep_assignments_are_refused() -> None:
    head = BICEP_HEAD + f"= {{\n  roleDefinitionId: '{OWNER_ID}'\n"
    assert [f.rule for f in found({"m.bicep": "targetScope = 'subscription'\n" + head * 600})] == ["iam-unreadable"]
