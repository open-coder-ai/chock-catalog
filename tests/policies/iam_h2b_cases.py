"""Cases for the iam-policy-scan hardening: the review's catch and correct-work tables, rebuilt from their descriptions.

The review's probe files are not in the plan repository, so each case is written here from its table row. A case is
`(path, text)` or `(path, text, head_text)` when the file already exists in HEAD with `head_text`.
"""

from __future__ import annotations

import json

from policies.iamkit import gate

AWS_ACCOUNT = "111122223333"  # the AWS documentation's example account
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # the built-in Owner role id, as the Azure tests spell it


def policy(*statements: dict, indent: int = 2) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)}, indent=indent) + "\n"


def allow(actions: object, resources: object = "*", **more: object) -> dict:
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **more}


ADMIN_BLOCK_YAML = (
    "Resources:\n  Role:\n    Type: AWS::IAM::Role\n    Properties:\n      Policies:\n        - PolicyName: all\n"
    "          PolicyDocument:\n            Version: '2012-10-17'\n            Statement:\n"
    "              - Effect: Allow\n                Action:\n                  - '*'\n                Resource: '*'\n"
)
NOT_ACTION_YAML = "Statement:\n  - Effect: Allow\n    NotAction:\n      - iam:*\n    Resource: '*'\n"
CLUSTER_ROLE_LIST = (
    "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: ops\nrules:\n"
    "  - apiGroups:\n      - ''\n    resources:\n      - pods\n    verbs:\n      - '*'\n"
)
ROLE_STAR_VERBS = (
    "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: ops\nrules:\n"
    '  - apiGroups: [""]\n    resources: ["pods"]\n    verbs: ["*"]\n'
)
CLUSTER_ADMIN_BINDING = (
    "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: ops\nroleRef:\n"
    "  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n"
    "  - kind: User\n    name: dana\n"
)
BICEP_OWNER = (
    "targetScope = 'subscription'\n\nresource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n"
    "  name: guid('x')\n  properties: {\n    roleDefinitionId: subscriptionResourceId("
    f"'Microsoft.Authorization/roleDefinitions', '{OWNER}')\n  }}\n}}\n"
)
ANCHOR_YAML = "x: &a '*'\nStatement:\n  - Effect: Allow\n    Action: *a\n    Resource: '*'\n"
TF_READ = (
    'data "aws_iam_policy_document" "read" {\n  statement {\n    effect    = "Allow"\n'
    '    actions   = ["ec2:DescribeInstances", "s3:ListAllMyBuckets"]\n    resources = ["*"]\n  }\n}\n'
)
TF_WRITE = (
    'data "aws_iam_policy_document" "writer" {\n  statement {\n    effect    = "Allow"\n'
    '    actions   = ["s3:PutObject", "s3:DeleteObject"]\n    resources = ["*"]\n  }\n}\n'
)
TF_PASSROLE = (
    'resource "aws_iam_policy" "p" {\n  name   = "p"\n  policy = jsonencode({\n    Version = "2012-10-17"\n'
    '    Statement = [{ Effect = "Allow", Action = ["iam:PassRole"], Resource = "*" }]\n  })\n}\n'
)
TF_ADMIN_ATTACHED = (
    'resource "aws_iam_role_policy_attachment" "admin" {\n  role       = aws_iam_role.deploy.name\n'
    '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}\n'
)
CFN_ADMIN_ATTACHED = (
    "Resources:\n  DeployRole:\n    Type: AWS::IAM::Role\n    Properties:\n      RoleName: deploy\n"
    "      ManagedPolicyArns:\n        - arn:aws:iam::aws:policy/AdministratorAccess\n"
)
TF_PRINCIPAL_STAR = (
    'data "aws_iam_policy_document" "pub" {\n  statement {\n    effect = "Allow"\n    actions = ["s3:GetObject"]\n'
    '    resources = ["arn:aws:s3:::b/*"]\n    principals {\n      type        = "AWS"\n      identifiers = ["*"]\n'
    "    }\n  }\n}\n"
)
TF_K8S_BINDING = (
    'resource "kubernetes_cluster_role_binding" "b" {\n  metadata { name = "b" }\n  role_ref {\n'
    '    api_group = "rbac.authorization.k8s.io"\n    kind = "ClusterRole"\n    name = "cluster-admin"\n  }\n}\n'
)
TF_GCP_OWNER = (
    'resource "google_project_iam_member" "m" {\n  role = "roles/owner"\n  member = "user:a@example.com"\n}\n'
)
GCP_YAML = "bindings:\n  - role: roles/owner\n    members:\n      - user:a@example.com\n"
AZURE_ROLE_JSON = json.dumps(
    {"Name": "all", "IsCustom": True, "Actions": ["*"], "AssignableScopes": ["/subscriptions/x"]}
)
TF_VAR_DEFAULT = (
    'variable "acts" {\n  default = ["*"]\n}\n\ndata "aws_iam_policy_document" "d" {\n  statement {\n'
    '    effect = "Allow"\n    actions = var.acts\n    resources = ["*"]\n  }\n}\n'
)

#: id -> (path, text, caught after the change). `False` is a miss the policy states and this item leaves alone.
CATCH = {
    "I01": ("iam/admin.json", policy(allow(["*"])), True),
    "I01v": ("template.yaml", ADMIN_BLOCK_YAML, True),
    "I02": ("iam/writer.json", policy(allow(["s3:PutObject", "s3:DeleteObject"])), True),
    "I02v": ("iam.tf", TF_WRITE, True),
    "I03": (
        "bucket.json",
        policy({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}),
        True,
    ),
    "I03v": ("pub.tf", TF_PRINCIPAL_STAR, True),
    "I04": ("iam/pass.json", policy(allow("iam:PassRole")), True),
    "I04v": ("pass.tf", TF_PASSROLE, True),
    "I05": ("iam/inverted.json", policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}), True),
    "I05v": ("inverted.yaml", NOT_ACTION_YAML, True),
    "I06": ("k8s/role.yaml", ROLE_STAR_VERBS, True),
    "I06v": ("k8s/clusterrole.yaml", CLUSTER_ROLE_LIST, True),
    "I07": ("k8s/binding.yaml", CLUSTER_ADMIN_BINDING, True),
    "I07v": ("rbac.tf", TF_K8S_BINDING, False),
    "I08": ("gcp.tf", TF_GCP_OWNER, False),
    "I08v": ("gcp.yaml", GCP_YAML, False),
    "I09": ("azure/role.json", AZURE_ROLE_JSON, False),
    "I09v": ("main.bicep", BICEP_OWNER, True),
    "I10": ("attach.tf", TF_ADMIN_ATTACHED, True),
    "I10v": ("stack.yaml", CFN_ADMIN_ATTACHED, True),
    "I11": ("iam/s3.json", policy(allow("s3:*")), True),
    "I11v": ("iam/svc.json", policy(allow(["lambda:*", "secretsmanager:*"])), True),
    "I12": ("var.tf", TF_VAR_DEFAULT, False),
    "I12v": ("anchor.yaml", ANCHOR_YAML, True),
}

LEGACY_ADMIN = policy(allow(["*"]))
LEGACY_SCOPED = policy(allow(["*"]), allow("s3:GetObject", "arn:aws:s3:::b/*"))
LEGACY_SID = policy({"Sid": "Legacy", **allow(["*"])})
TLS_DENY = policy(
    {
        "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
)  # fmt: skip
SCP_DENY = policy(
    {
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]}},
    }
)  # fmt: skip
KMS_DEFAULT = policy(
    {
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT}:root"}, "Action": "kms:*",
        "Resource": "*",
    }
)  # fmt: skip

#: id -> (path, text, head text or None, refused today). The refusals that stay (N07, N12) are item 3 "further".
CORRECT = {
    "N01": ("iam/read.json", policy(allow(["ec2:DescribeInstances", "s3:ListAllMyBuckets", "sts:GetCallerIdentity"])),
            None, False),
    "N02": ("read.tf", TF_READ, None, False),
    "N03": ("iam/scoped.json", policy(allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::b/*")), None, False),
    "N04": ("scoped.tf", 'data "aws_iam_policy_document" "d" {\n  statement {\n    effect = "Allow"\n'
            '    actions = ["s3:GetObject"]\n    resources = ["${aws_s3_bucket.b.arn}/*"]\n  }\n}\n', None, False),
    "N05": ("iam/tls.json", TLS_DENY, None, False),
    "N06": ("iam/scp.json", SCP_DENY, None, False),
    "N07": ("kms/key.json", KMS_DEFAULT, None, True),
    "N08": ("iam/org.json", policy({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::b/*",
                                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}}),
            None, False),
    "N09": ("iam/trust.json", policy({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                      "Action": "sts:AssumeRole"}), None, False),
    "N10": ("commented.tf", '# never write actions = ["*"] with resources = ["*"]\n' + TF_READ, None, False),
    "N11": ("docs/iam.md", "```json\n" + policy(allow(["*"])) + "```\n", None, False),
    "N12": ("tests/fixtures/overbroad_policy.json", policy(allow(["*"])), None, True),
    "N13": ("k8s/reader.yaml", "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: r\nrules:\n"
            '  - apiGroups: [""]\n    resources: ["pods"]\n    verbs: ["get", "list"]\n', None, False),
    "N14": ("k8s/view.yaml", CLUSTER_ADMIN_BINDING.replace("cluster-admin", "view"), None, False),
    "N15": ("gcp-narrow.tf", 'resource "google_project_iam_member" "m" {\n  role = "roles/storage.objectViewer"\n'
            '  member = "serviceAccount:a@p.iam.gserviceaccount.com"\n}\n', None, False),
    "N16": ("reader.tf", 'resource "azurerm_role_assignment" "r" {\n  scope = azurerm_resource_group.rg.id\n'
            '  role_definition_name = "Reader"\n  principal_id = var.pid\n}\n', None, False),
    "N17": ("iam/legacy.json", LEGACY_SCOPED, LEGACY_ADMIN, False),
    "N18": ("iam/legacy.json", policy(allow(["*"]), indent=4), LEGACY_ADMIN, False),
    "N19": ("iam/legacy.json", LEGACY_SID, LEGACY_ADMIN, False),
    "N20": ("stack.py", 'role.add_to_policy(iam.PolicyStatement(actions=["s3:GetObject"], resources=[bucket.arn]))\n',
            None, False),
    "N21": ("cors.json", json.dumps([{"AllowedHeaders": ["*"], "AllowedMethods": ["GET"], "AllowedOrigins": ["*"]}]),
            None, False),
    "N22": ("webhook.yaml", "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\n"
            "metadata:\n  name: w\nwebhooks:\n  - name: w.example.com\n    rules:\n      - apiGroups: ['*']\n"
            "        apiVersions: ['*']\n        operations: ['CREATE']\n        resources: ['*']\n", None, False),
    "N23": ("iam/logs.json", policy(allow(["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"])),
            None, False),
    "N24": ("tests/test_scan.py", 'def test_rejects():\n    assert scan({"Effect": "Allow", "Action": "*"})\n',
            None, False),
    "N25": ("contrib.bicep", "targetScope = 'resourceGroup'\n\nresource ra 'Microsoft.Authorization/roleAssignments"
            "@2022-04-01' = {\n  name: guid('x')\n  properties: {\n    roleDefinitionId: subscriptionResourceId("
            "'Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')\n  }\n}\n", None, False),
    "N26": ("values.yaml", "rbac:\n  groups:\n    - name: cluster-admin-readonly\n      users: [dana]\n", None, False),
}  # fmt: skip

#: Files the review's near-miss table (PSn) sets beside the N cases; `refused` is what the item asks for.
RECORD = '{"id": %d, "effect": "positive", "principal": "user-%d", "note": "%s"}'
PAD = "x" * 200


def data_json(edited: int = -1) -> str:
    rows = [RECORD % (i, i, "edited" if i == edited else PAD) for i in range(6000)]
    return "[\n" + ",\n".join(rows) + "\n]\n"


GO_TEMPLATED_ROLE = (
    "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: {{ .Release.Name }}-reader\n"
    '  namespace: {{ .Release.Namespace }}\nrules:\n  - apiGroups: [""]\n    resources: ["configmaps"]\n'
    '    verbs: ["get", "list"]\n'
)
NAN_JSON = '{"effect": "ok", "value": NaN}\n'


def added(path: str, text: str, head: str | None = None) -> list:
    """The findings a change adds: those in the new text whose rule and id the old text does not already hold."""
    old = {f.key for f in gate.scan_file(path, head)} if head is not None else set()
    return [f for f in gate.scan_file(path, text) if f.key not in old]


def rule_of(path: str, text: str) -> tuple[str, str]:
    (finding,) = gate.scan_file(path, text)
    return finding.rule, finding.tier
