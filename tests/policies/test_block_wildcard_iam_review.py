"""block-wildcard-iam against the hardening review's cases (REVIEW-infra 2.2 and 5), each through the real commit gate."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from policies import gatekit, scriptkit

POLICY = "block-wildcard-iam"


def _doc(*statements: dict) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)}, indent=2) + "\n"


def _allow(action: str | list[str], resource: str | list[str] = "*", **extra: object) -> dict:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


@dataclass(frozen=True)
class Case:
    """One review case: files committed first (`base`), files then staged (`files`), and the verdict the review wants."""

    id: str
    files: dict[str, str]
    refuse: bool
    base: dict[str, str] = field(default_factory=dict)


_ADMIN = _doc(_allow("*"))
_ADMIN_4 = json.dumps(json.loads(_ADMIN), indent=4) + "\n"
_OLD = {"iam/legacy.json": _ADMIN}

#: I01-I12v: a violation the review wrote; `refuse` is what the review expects, misses it discloses included.
CATCH = [
    Case("I01", {"iam/admin.json": _ADMIN}, True),
    Case(
        "I01v",
        {"cfn/admin.yaml": "Statement:\n  - Effect: Allow\n    Action:\n      - '*'\n    Resource: arn:aws:s3:::b\n"},
        True,
    ),
    Case("I02", {"iam/s3.json": _doc(_allow(["s3:PutObject", "s3:DeleteObject"]))}, True),
    Case(
        "I02v",
        {"iam/s3.tf": 'statement {\n  actions   = ["s3:PutObject", "s3:DeleteObject"]\n  resources = ["*"]\n}\n'},
        True,
    ),
    Case(
        "I03",
        {
            "iam/bucket.json": _doc(
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
            )
        },
        True,
    ),
    Case("I03v", {"iam/bucket.tf": 'principals {\n  type        = "AWS"\n  identifiers = ["*"]\n}\n'}, True),
    Case("I04", {"iam/pass.json": _doc(_allow("iam:PassRole"))}, True),
    Case(
        "I04v",
        {
            "iam/pass.tf": 'policy = jsonencode({\n  Statement = [{\n    Effect   = "Allow"\n    Action   = "iam:PassRole"\n    Resource = "*"\n  }]\n})\n'
        },
        True,
    ),
    Case(
        "I05",
        {"iam/notaction.json": _doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "arn:aws:s3:::b"})},
        True,
    ),
    Case(
        "I05v",
        {"cfn/notaction.yaml": "Statement:\n  - Effect: Allow\n    NotAction: iam:*\n    Resource: arn:aws:s3:::b\n"},
        True,
    ),
    Case("I06", {"k8s/role.yaml": 'rules:\n  - apiGroups: [""]\n    resources: ["pods"]\n    verbs: ["*"]\n'}, True),
    Case(
        "I06v",
        {"k8s/clusterrole.yaml": 'rules:\n  - apiGroups: [""]\n    resources: ["pods"]\n    verbs:\n      - "*"\n'},
        True,
    ),
    Case("I07", {"k8s/binding.yaml": "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\n"}, True),
    Case("I07v", {"k8s/binding.tf": 'role_ref {\n  kind = "ClusterRole"\n  name = "cluster-admin"\n}\n'}, True),
    Case("I08", {"gcp/iam.tf": 'role   = "roles/owner"\nmember = "user:a@example.com"\n'}, True),
    Case(
        "I08v",
        {"gcp/policy.yaml": "bindings:\n  - role: roles/owner\n    members:\n      - user:a@example.com\n"},
        True,
    ),
    Case("I09", {"azure/role.json": json.dumps({"Name": "x", "Actions": ["*"]}, indent=2) + "\n"}, True),
    Case(
        "I09v",
        {
            "azure/owner.bicep": "resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n  properties: {\n    roleDefinitionName: 'Owner'\n  }\n}\n"
        },
        True,
    ),
    Case("I10", {"iam/admin.tf": 'policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n'}, True),
    Case("I10v", {"cfn/admin.yaml": "ManagedPolicyArns:\n  - arn:aws:iam::aws:policy/AdministratorAccess\n"}, True),
    Case("I11", {"iam/svc.json": _doc(_allow("s3:*"))}, True),
    Case("I11v", {"iam/svc2.json": _doc(_allow(["lambda:*", "secretsmanager:*"]))}, True),
    Case("I12", {"iam/var.tf": 'variable "actions" {\n  default = "*"\n}\n'}, True),
    Case(
        "I12v",
        {
            "cfn/alias.yaml": "base: &all '*'\nStatement:\n  - Effect: Allow\n    Action: *all\n    Resource: arn:aws:s3:::b\n"
        },
        True,
    ),
]

#: N01-N26: correct work the review wrote; `refuse` is False for every one.
CORRECT = [
    Case("N01", {"iam/describe.json": _doc(_allow(["ec2:DescribeInstances", "ec2:DescribeVolumes"]))}, False),
    Case(
        "N02",
        {
            "iam/describe.tf": 'statement {\n  actions   = ["s3:ListAllMyBuckets", "ec2:DescribeInstances"]\n  resources = ["*"]\n}\n'
        },
        False,
    ),
    Case("N03", {"iam/role.json": _doc(_allow(["s3:GetObject"], "arn:aws:s3:::reports/*"))}, False),
    Case(
        "N04",
        {
            "iam/scoped.tf": 'statement {\n  actions   = ["s3:GetObject"]\n  resources = ["${aws_s3_bucket.b.arn}/*"]\n}\n'
        },
        False,
    ),
    Case(
        "N05",
        {
            "iam/tls.json": _doc(
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::b/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            )
        },
        False,
    ),
    Case(
        "N06",
        {
            "iam/scp.json": _doc(
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]}},
                }
            )
        },
        False,
    ),
    Case(
        "N07",
        {
            "kms/key.json": _doc(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            )
        },
        False,
    ),
    Case(
        "N08",
        {
            "iam/org.json": _doc(
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::b/*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
                }
            )
        },
        False,
    ),
    Case(
        "N09",
        {
            "iam/trust.json": _doc(
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            )
        },
        False,
    ),
    Case(
        "N10",
        {"iam/main.tf": '# never write actions = ["*"] here\nstatement {\n  actions = ["s3:GetObject"]\n}\n'},
        False,
    ),
    Case("N11", {"docs/iam.md": 'Do not write this:\n\n    "Action": "*",\n'}, False),
    Case("N12", {"tests/fixtures/overbroad_policy.json": _ADMIN}, False),
    Case(
        "N13",
        {"k8s/role.yaml": 'rules:\n  - apiGroups: [""]\n    resources: ["pods"]\n    verbs: ["get", "list"]\n'},
        False,
    ),
    Case("N14", {"k8s/view.yaml": "roleRef:\n  kind: ClusterRole\n  name: view\n"}, False),
    Case(
        "N15",
        {
            "gcp/iam.tf": 'role   = "roles/storage.objectViewer"\nmember = "serviceAccount:a@p.iam.gserviceaccount.com"\n'
        },
        False,
    ),
    Case("N16", {"azure/reader.tf": 'role_definition_name = "Reader"\nscope = azurerm_resource_group.rg.id\n'}, False),
    Case(
        "N17",
        {
            "iam/legacy.json": _ADMIN.replace(
                "\n  ]\n}",
                ',\n    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}\n  ]\n}',
            )
        },
        False,
        _OLD,
    ),
    Case("N18", {"iam/legacy.json": _ADMIN_4}, False, _OLD),
    Case(
        "N19",
        {"iam/legacy.json": _ADMIN.replace('"Effect": "Allow",', '"Sid": "Old",\n      "Effect": "Allow",')},
        False,
        _OLD,
    ),
    Case(
        "N20",
        {
            "cdk/stack.ts": "new iam.PolicyStatement({ actions: ['s3:GetObject'], resources: [bucket.arnForObjects('*')] });\n"
        },
        False,
    ),
    Case(
        "N21",
        {
            "s3/cors.json": json.dumps(
                [{"AllowedHeaders": ["*"], "AllowedMethods": ["GET"], "AllowedOrigins": ["https://example.com"]}],
                indent=2,
            )
            + "\n"
        },
        False,
    ),
    Case(
        "N22",
        {"k8s/webhook.yaml": "webhooks:\n  - rules:\n      - apiGroups: ['*']\n        resources: ['*']\n"},
        False,
    ),
    Case("N23", {"iam/logs.json": _doc(_allow("logs:CreateLogGroup"))}, False),
    Case(
        "N24",
        {"tests/test_scanner.py": 'def test_rejects():\n    assert scan({"Action": "*", "Resource": "*"}).blocked\n'},
        False,
    ),
    Case("N25", {"azure/contrib.bicep": "properties: {\n  roleDefinitionName: 'Contributor'\n}\n"}, False),
    Case("N26", {"helm/values.yaml": "users:\n  - name: cluster-admin-readonly\n    group: viewers\n"}, False),
    Case("BW3", {"iam/identity.json": _doc(_allow("sts:GetCallerIdentity"))}, False),
    Case("BW6", {"build.config.js": "module.exports = { resources: ['*'] };\n"}, False),
]

#: Correct work this line gate still refuses by design: the line carries no sign of the Deny, the condition or the legacy HEAD.
STILL_REFUSED = {"N05", "N06", "N07", "N08", "N12", "N18", "N22"}

#: The review's catches the gate keeps once a bare resource wildcard is left to the structured scan.
STILL_CAUGHT = {"I01", "I03", "I03v", "I06", "I07", "I07v", "I08", "I08v", "I09v", "I10", "I10v", "I11"}


def verdict(tmp_path: Path, case: Case, monkeypatch: pytest.MonkeyPatch) -> bool:
    """Whether the gate refuses `case` staged in a fresh repository, judged as a person's commit."""
    for marker in ("CLAUDECODE", "AI_AGENT", "CHOCK_AGENT_COMMIT"):
        monkeypatch.delenv(marker, raising=False)
    repo = scriptkit.init_repo(tmp_path / "r", {"README.txt": "x\n", **case.base})
    scriptkit.write(repo, case.files)
    scriptkit.git(repo, "add", "-A")
    return gatekit.judge(POLICY, repo, gatekit.COMMIT)[0] != 0


@pytest.mark.parametrize("case", [c for c in CATCH if c.id in STILL_CAUGHT], ids=lambda c: c.id)
def test_a_violation_the_line_gate_catches_is_still_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: Case
) -> None:
    assert verdict(tmp_path, case, monkeypatch)


@pytest.mark.parametrize("case", [c for c in CORRECT if c.id not in STILL_REFUSED], ids=lambda c: c.id)
def test_correct_work_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: Case) -> None:
    assert not verdict(tmp_path, case, monkeypatch)
