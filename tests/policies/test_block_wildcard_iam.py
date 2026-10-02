"""block-wildcard-iam v2: the single-line grant forms it refuses, the code it leaves alone, and its own source."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest
from policies import gatekit, scriptkit

POLICY = "block-wildcard-iam"
SPEC = gatekit.gate_spec(POLICY)
PATTERN = re.compile(SPEC["params"]["content_pattern"])
PRAGMA = re.compile(SPEC["params"]["allowlist_pragma"])

BLOCKED = [
    r'{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::reports"}',
    r'"Action": ["*"],',
    r'"Action": [ "*" ],',
    r'"Action": ["s3:GetObject", "*"],',
    r'"Resource": ["*"]',
    r'"Action":"*"',
    '"Action"\t:\t"*",',
    r"'Action': '*'",
    r'Action: "*"',
    r"Action: '*'",
    r"Action: *",
    r"Action: ['*']",
    r'  Action: "*" # comment',
    r'"Action": "*:*"',
    r'"Action": ["*:*"]',
    r'"Action": "s3:*",',
    r'"Action": ["iam:*", "s3:GetObject"]',
    r'      "iam:*",',
    r'  - "sts:*"',
    r"  - kms:*",
    r"Action: ec2:*",
    r'"Action": "IAM:*"',
    r'"Principal": "*"',
    r'"Principal": {"AWS": "*"}',
    r"Principal: {AWS: ['*']}",
    r'"Principal": {"AWS": ["arn:aws:iam::1:root", "*"]}',
    r'{"Effect": "Allow", "NotAction": "iam:*", "Resource": "arn:aws:s3:::b"}',
    r'{"Effect": "Allow", "NotAction": ["iam:DeleteRole"], "Resource": "arn:aws:s3:::b"}',
    r'{"Effect": "Allow", "NotResource": "arn:aws:s3:::b", "Action": "s3:GetObject"}',
    r'policy = "{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}"',
    r'"Action": "\u002a"',
    r'actions = ["*"]',
    r'actions   =   [ "*" ]',
    r'resources = ["*"]',
    r'actions = ["s3:GetObject", "*"]',
    r'identifiers = ["*"]',
    r"actions: ['*'],",
    r"new iam.PolicyStatement({ actions: ['*'], resources: ['*'] })",
    r'iam.PolicyStatement(actions=["*"], resources=["*"])',
    r"effect: iam.Effect.ALLOW, actions: ['*']",
    r'policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"',
    r"- arn:aws:iam::aws:policy/PowerUserAccess",
    r'ManagedPolicyArns: [!Sub "arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess"]',
    r'"arn:aws-us-gov:iam::aws:policy/IAMFullAccess"',
    r'name = "AdministratorAccess"',
    r"gcloud projects add-iam-policy-binding $P --member=$SA --role='roles/owner'",
    r"gcloud projects add-iam-policy-binding $P --member=$SA --role=roles/editor",
    r"gcloud projects add-iam-policy-binding $P --member=$SA --role roles/owner",
    r"- role: roles/owner",
    r'role = "roles/editor"',
    r'"role": "roles/owner",',
    r'members = ["allUsers"]',
    r'member  = "allAuthenticatedUsers"',
    r'"members": ["user:a@b.c", "allUsers"],',
    r"gcloud storage buckets add-iam-policy-binding gs://b --member=allUsers --role=roles/storage.objectViewer",
    r"- allUsers",
    r'  - "allAuthenticatedUsers"',
    r"gsutil iam ch allUsers:objectViewer gs://bucket",
    r'verbs: ["*"]',
    r"verbs: ['*']",
    r'"verbs": ["get", "*"]',
    r'apiGroups: ["*"]',
    r'resources: ["*"]',
    r"kubectl create clusterrolebinding ci --clusterrole=cluster-admin --serviceaccount=ci:ci",
    r"  name: cluster-admin",
    r'name = "cluster-admin"',
    r'"name": "cluster-admin",',
    r'"actions": ["*"],',
    r'"Actions": ["*"],',
    r'"dataActions": ["*"]',
    r'role_definition_name = "Owner"',
    r"roleDefinitionName: 'Owner'",
    r"az role assignment create --assignee $SP --role Owner --scope /subscriptions/x",
    r'az role assignment create --assignee $SP --role "Owner"',
    "roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
    "'8e3af657-a8ff-443c-a75c-2fe8c4bcb635')",
    # A Deny smuggled into a string value does not make the line a Deny statement.
    r'{"Sid": "Effect: Deny", "Effect": "Allow", "Action": "*", "Resource": "*"}',
    r"{Sid: 'Effect: Deny', Action: '*', Resource: '*'}",
    r"new iam.PolicyStatement({ sid: 'Effect.DENY', actions: ['*'], resources: ['*'] })",
    r"new iam.PolicyStatement({ sid: 'effect: iam.Effect.DENY', actions: ['*'] })",
    r'{"Sid": "\"Effect\": \"Deny\"", "Action": "*", "Resource": "*"}',
    r"{Effect: Deny, Action: '*', Resource: '*'}",
    r'jsonencode({ Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }] })',
    r'policy = "{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}"',
    r"new iam.PolicyStatement({ effect: iam.Effect.DENY, actions: ['*'], resources: ['*'] })",
    # A Deny in a comment, a second statement, an escaped Allow or a string does not make a Deny line.
    r'data "aws_iam_policy_document" "a" { statement { actions = ["*"] resources = ["*"] } } # Effect = Deny',
    r"role.addToPolicy(new iam.PolicyStatement({ actions: ['*'], resources: ['*'] })); // effect: Deny",
    r"  Action: '*'  # Effect: Deny",
    r'iam.PolicyStatement(actions=["*"], resources=["*"])  # effect=Deny',
    r'resources = ["*"] # Effect = Deny',
    r"new iam.PolicyStatement({ effect: iam.Effect.DENY, actions: ['s3:x'] }); "
    r"new iam.PolicyStatement({ actions: ['*'], resources: ['*'] });",
    r'{"Statement":[{"Effect":"Deny","Action":"x:Y","Resource":"*"},{"Effect":"\u0041llow","Action":"*","Resource":"*"}]}',
    r'{"Effect": "Deny", "Action": "x:Y", "Resource": "*"}, {"Action": "*", "Resource": "*"}',
    r'{"Effect": "Deny", "Sid": "x", "Effect": "Allow", "Action": "*", "Resource": "*"}',
    r'{"Sid": "ops Effect: Deny", "Effect": "Allow", "Action": "*", "Resource": "*"}',
    r'{"Effect": "Deny", "Action": "*", "Resource": "*"} // trailing',
    # A quoted wildcard followed by a comment or more text.
    r"Action: '*' // all",
    r'"Action": "*" /* all */',
    r"Action: '*' -- x",
    r'"Resource": "*" + suffix',
    r"Policies: [AdministratorAccess]",
    r"Policies: AdministratorAccess",
    r"  - AdministratorAccess",
    r"--policy-name PowerUserAccess",
    r"member: allUsers",
    r"members: [allUsers]",
    r"gsutil acl ch -u AllUsers:R gs://b",
    r"gsutil iam ch allUsers:roles/storage.objectViewer gs://b",
    r'role_definition_id = "8E3AF657-A8FF-443C-A75C-2FE8C4BCB635"',
    r"principals: [new iam.AnyPrincipal()]",
    r"iam.StarPrincipal()",
    r'"Principal": {"Federated": "*"}',
    r"roleRef: {kind: ClusterRole, name: cluster-admin}",
    r"roleDefinitionName: Owner",
    r'    {"Effect": "Deny", "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},',
    r'{"Effect": "Deny", "rules": [ "x", {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}',
    r'{"Effect": "Deny", "x": 1, "permissions": [ "", {"actions": ["*"]}]}',
    r'{"Effect": "Deny", "Action": "x:Y", "Resource": "x"}; grant(actions=["*"], resource_arns=["*"])  # }',
    r'{"Effect": "Deny", "Action": "x:Y", "Resource": "x", "_": grant(actions=["*"], resource_arns=["*"])}',
    r'{"Effect": "Deny", "Action": "x:Y", "Resource": "x"} {"Action": "*", "Resource": "*"}',
]

ALLOWED = [
    r'{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"}',
    r'"Resource": "arn:aws:s3:::bucket/*"',
    r'"Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]',
    r'{"Effect": "Deny", "Action": "*", "Resource": "*"}',
    r'{"Effect": "Deny", "NotAction": ["iam:*", "sts:*"], "Resource": "*"}',
    r'{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}',
    r'{"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::b/*"}',
    r'actions = ["s3:GetObject"]',
    r'resource "aws_iam_role" "owner" {',
    r'  name = "report-owner"',
    r'"Action": ["s3:GetObject", "s3:PutObject"],',
    r'redis.keys("session:*")',
    r'r.scan_iter(match="user:*")',
    r'params = {"q": "*:*"}',
    r'"build:*": "run-p build:*",',
    r"const allUsers = await db.users();",
    r"const members = allUsers.filter(u => u.active);",
    r"state.allUsers = []",
    r"roles/owner is a basic role you should never grant",
    r"See roles/owner and roles/editor in the docs.",
    r'"role": "roles/viewer",',
    r"- role: roles/storage.objectViewer",
    r"name: cluster-admin-readonly",
    r"name: cluster-admins",
    r'role_definition_name = "Reader"',
    r'role_definition_name = "Contributor"',
    r'az role assignment create --role "Storage Blob Data Reader"',
    r"--role OwnerReader",
    r'glob("src/**/*.py")',
    r'import * as fs from "fs";',
    r"SELECT * FROM t WHERE a = '*'",
    r"resources: {limits: {cpu: '1'}}",
    r'"permissions": {"contents": "read", "actions": "write"}',
    r'apiGroups: [""]',
    r'verbs: ["get", "list", "watch"]',
    r'"effect": "Allow", "actions": ["read"]',
    r"Action: s3:GetObject",
    r'pattern = "*"',
    r"x = a * b",
    r'"Resource": "*.example.com"',
    r'cron: "*/5 * * * *"',
    r'"Principal": {"Service": "lambda.amazonaws.com"}',
    r"grant iam:* to admins in prose",
    r"AdministratorAccess is the managed policy name",
    r'"Action": "iam:*Policy"',
    r"redis.keys('ec2:*')",
    r'cache.delete_pattern("iam:*")',
    r"keys = ['s3:*', 'iam:*']",
    r'"scripts": { "s3:*": "aws s3 sync" }',
    r'logger = logging.getLogger("iam:*")',
    r"- name: cluster-admin",
    r"metadata: {name: cluster-admin}",
    r"helm install x --set name=cluster-admin",
    r'DENYLIST = {"AdministratorAccess", "PowerUserAccess"}',
    r'if policy == "AdministratorAccess":',
    r'label: "AdministratorAccess"',
    r'    "allUsers",',
    r"python manage.py createuser --role Owner bob",
    r'{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": "eu-west-1"}}},',
    r"- AdministratorAccess is too broad",
    r"az role assignment list --role Owner",
    r"az role assignment delete --assignee $SP --role Owner",
]

# Each took 10 to 50 seconds before every look-ahead scan was bounded.
PATHOLOGICAL = [
    '"Action": [' * 10000,
    "members: [" * 10000,
    "members: " * 20000,
    "[ ," * 100000,
    "a" * 1000000,
    " Policies:" * 8000,
    " roleRef:" * 8000,
    " role_ref {" * 8000,
    " az role assignment create" * 6000,
]


@pytest.mark.parametrize("line", BLOCKED)
def test_a_broad_grant_on_one_line_is_refused(line: str) -> None:
    assert PATTERN.search(line), line


@pytest.mark.parametrize("line", ALLOWED)
def test_a_scoped_grant_a_deny_or_ordinary_code_is_left_alone(line: str) -> None:
    assert not PATTERN.search(line), line


def test_the_pragma_names_the_waiver() -> None:
    assert PRAGMA.search('"Action": "*"  # pragma: allowlist broad-privilege')


@pytest.mark.parametrize("text", PATHOLOGICAL, ids=range(len(PATHOLOGICAL)))
def test_a_hostile_line_is_judged_in_bounded_time(text: str) -> None:
    started = time.monotonic()
    PATTERN.search(text)
    assert time.monotonic() - started < 5


def _own_lines() -> list[str]:
    folder = gatekit.policy_dir(POLICY)
    lines = [ln for p in sorted(folder.rglob("*")) if p.is_file() for ln in p.read_text(encoding="utf-8").splitlines()]
    return [*lines, json.dumps(SPEC)]


def test_the_policy_never_matches_its_own_source_or_compiled_gate() -> None:
    hits = [ln for ln in _own_lines() if PATTERN.search(ln) and not PRAGMA.search(ln)]
    assert hits == []


def test_a_commit_is_refused_and_a_person_s_waiver_lets_it_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for marker in ("CLAUDECODE", "AI_AGENT", "CHOCK_AGENT_COMMIT"):
        monkeypatch.delenv(marker, raising=False)
    repo = scriptkit.init_repo(tmp_path / "r", {"README.txt": "x\n"})
    scriptkit.write(repo, {"policy.json": '{"Effect": "Allow", "Action": ["*"], "Resource": "*"}\n'})
    scriptkit.git(repo, "add", "policy.json")
    code, err = gatekit.judge(POLICY, repo, gatekit.COMMIT)
    assert code == 1 and "policy.json" in err
    scriptkit.write(repo, {"policy.json": 'Action: ["*"]  # pragma: allowlist broad-privilege\n'})
    scriptkit.git(repo, "add", "policy.json")
    assert gatekit.judge(POLICY, repo, gatekit.COMMIT)[0] == 0
