"""AWS managed policies attached by ARN: the administrator policy, wherever the attachment is written."""

from __future__ import annotations

import re

from iamscan.access import entries, literals

#: The AWS-owned account segment is empty and the policy path is the whole name, so a customer policy of the same
#: name (`arn:aws:iam::123456789012:policy/AdministratorAccess`) and `AdministratorAccessFoo` do not match.
ADMIN_ARN = re.compile(r"(?i)arn:\S*?:iam::aws:policy/AdministratorAccess")
#: Keys that attach a managed policy: Terraform attributes, CloudFormation properties and their JSON spellings.
ATTACH_KEYS = frozenset(
    {"policy_arn", "policy_arns", "managed_policy_arn", "managed_policy_arns", "managedpolicyarns", "managedpolicies",
     "managedpolicyarn", "policyarn", "policyarns"}
)  # fmt: skip
#: Keys that say what the attachment is for, so two roles given the same policy are two findings.
NAMES = frozenset(
    {"rolename", "username", "groupname", "name", "role", "roles", "user", "users", "group", "groups", "permissionsetname"}
)  # fmt: skip


def names_admin(value: str) -> bool:
    """Whether one string is the administrator policy's ARN, with the partition spelled out or interpolated."""
    return ADMIN_ARN.fullmatch(value.strip()) is not None


def attached(node: dict) -> tuple[str, object] | None:
    """(the attaching key, what the attachment is about) when a mapping attaches AdministratorAccess, else None."""
    for key, value in node.items():
        if isinstance(key, str) and key.lower() in ATTACH_KEYS and any(names_admin(s) for s in literals(value)):
            about = [literals(entries(node, name)) for name in sorted(NAMES)]
            return key.lower(), [key.lower(), about]
    return None
