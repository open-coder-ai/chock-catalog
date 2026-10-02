"""What a finding is, and the rules it can name."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

BLOCK, ASK = "block", "ask"

#: rule id -> what is wrong and what to do instead; a rule's tier is chosen where it fires.
RULES = {
    "iam-admin-grant": "Allow with Action '*' on every resource: administrator access. Name the actions and resources.",
    "iam-action-wildcard": "Allow with Action '*' on a named resource. Name the actions the task needs.",
    "iam-service-wildcard": "Allow with a whole-service action wildcard (s3:*, iam:*, sts:*, kms:*, ec2:*). "
    "Name the actions; on every resource it is refused, on a named one it asks.",
    "iam-allow-inverted": "Allow with NotAction, NotResource or NotPrincipal grants everything the key does not name. "
    "Allow the named actions, resources and principals instead.",
    "iam-principal-wildcard": "Allow for any principal with no Condition: public access. Name the principals or add a Condition.",
    "iam-trust-wildcard": "Role trust for any principal with no Condition that names who may assume it. "
    "Trust named principals, or require aws:PrincipalOrgID, aws:PrincipalArn or sts:ExternalId.",
    "iam-trust-cross-account": "Role trust of another account with no sts:ExternalId or aws:MultiFactorAuthPresent condition.",
    "azure-subscription-owner": "Owner or Contributor role assignment at subscription scope. Scope it to a resource group or resource.",
    "k8s-cluster-admin-binding": "Binding to the cluster-admin role. Bind a role that names the verbs and resources needed.",
    "k8s-rbac-wildcard": "RBAC rule with a wildcard verb, resource or apiGroup. Name them.",
    "iam-duplicate-key": "A key a policy is read by is given twice; loaders keep different ones. Give it once.",
    "iam-unreadable": "Cannot be read with certainty, so cannot be judged. Write it in plain JSON, YAML or HCL.",
}


@dataclass(frozen=True)
class Finding:
    """One broad grant: where it is, what it is (sig is a content id, so a moved grant is old), who may waive it."""

    rule: str
    tier: str
    path: str
    line: int
    sig: str
    anchors: tuple[int, ...] = ()
    hint: str = ""
    nth: int = -1  # which occurrence of the hint key in the file this is, for files that carry no line numbers

    @property
    def key(self) -> str:
        return f"{self.rule}|{self.sig}"

    def render(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] ({self.tier}; id {self.sig}) {RULES[self.rule]}"


def signature(value: object) -> str:
    """A stable id for a statement: its content without Sid, keys sorted, so reordering or renaming a Sid is not new."""
    body = json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), default=repr)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]


def _plain(value: object) -> object:
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items() if str(k).lower() != "sid"}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return str(value) if isinstance(value, str) else value
