"""AWS policy statements: what an Allow grants, whatever the layout it was written in."""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple

from iamscan.access import entries, key_names, literals, strings_of
from iamscan.model import ASK, BLOCK

STAR = frozenset({"*", "*:*"})
SERVICE_STAR = re.compile(r"(?i)(?:s3|iam|sts|kms|ec2):\*")
ASSUME = re.compile(r"(?i)sts:(?:\*|assumerole\w*)")
ACCOUNT = re.compile(r"(?:arn:[\w-]+:iam::)?\d{12}(?::|$)")
INVERTED = ("notaction", "notresource", "notprincipal")
#: Condition keys that say who may assume a role or reach a resource, so a wildcard principal is not public.
NAMES_THE_CALLER = frozenset(
    {
        "aws:principalorgid", "aws:principalorgpaths", "aws:principalarn", "aws:principalaccount",
        "aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths", "sts:externalid",
        "kms:calleraccount", "s3:dataaccesspointaccount", "aws:principalservicename", "aws:resourceaccount",
        "aws:resourceorgid",
    }
)  # fmt: skip
#: Keys that narrow who can reach a resource by where they come from, which suffices for a resource policy.
NAMES_THE_NETWORK = frozenset({"aws:sourcevpce", "aws:sourcevpc", "aws:sourceip", "aws:vpcsourceip"})
#: Operators that say "equal to this": a negated, Null or Bool operator narrows nothing about who the caller is.
POSITIVE_OPERATORS = frozenset(
    {"stringequals", "stringequalsignorecase", "stringlike", "arnequals", "arnlike", "ipaddress"}
)
EVERYONE = frozenset({"*", "0.0.0.0/0", "::/0"})
IP_KEYS = frozenset({"aws:sourceip", "aws:vpcsourceip"})
MIN_LITERAL = 3  # a value with fewer letters or digits than this ("o-*", "arn:*") names no one


class Hit(NamedTuple):
    rule: str
    tier: str
    hint: str  # the key to look for when the file carries no line numbers


def is_deny(statement: dict) -> bool:
    """True only when every Effect the statement gives, in any key case, is Deny."""
    effects = entries(statement, "effect")
    return bool(effects) and all(isinstance(e, str) and e.strip().lower() == "deny" for e in effects)


def is_statement(node: dict) -> bool:
    return bool(entries(node, "effect"))


def judge(statement: dict) -> list[Hit]:
    """The broad grants one statement makes; a Deny, and a statement with no Effect, make none."""
    if not is_statement(statement) or is_deny(statement):
        return []
    hits = [Hit("iam-allow-inverted", BLOCK, name) for name in INVERTED if any(k.lower() == name for k in statement)]
    return [*hits, *_actions(statement), *_principals(statement)]


def _all_resources(statement: dict) -> bool:
    return "*" in strings_of(statement, "resource")


def _actions(statement: dict) -> list[Hit]:
    actions = strings_of(statement, "action")
    everywhere = BLOCK if _all_resources(statement) else ASK
    if any(a in STAR for a in actions):
        return [Hit("iam-admin-grant" if everywhere == BLOCK else "iam-action-wildcard", everywhere, "action")]
    if any(SERVICE_STAR.fullmatch(a) for a in actions):
        return [Hit("iam-service-wildcard", everywhere, "action")]
    return []


def _wildcard_principal(principal: object) -> bool:
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, dict):
        return any(_wildcard_principal(v) for v in principal.values())
    if isinstance(principal, list | tuple):
        return any(_wildcard_principal(v) for v in principal)
    return False


def _foreign_account(principal: object) -> bool:
    if not isinstance(principal, dict):
        return False
    aws = [v for k, v in principal.items() if str(k).lower() == "aws"]
    return any(ACCOUNT.match(s.strip()) for s in literals(aws))


def _condition_keys(statement: dict) -> set[str] | None:
    """The condition keys the statement names, or None when it has no Condition (an empty one is none)."""
    present = [c for c in entries(statement, "condition") if c]
    return {k for c in present for k in key_names(c)} if present else None


def _acceptable(key: str, value: object) -> bool:
    """Whether a condition value narrows the caller: unknown (a reference) counts, only a literal everyone does not."""
    raw = value if isinstance(value, list | tuple) else [value]
    if not raw or any(not isinstance(v, str) or getattr(v, "ref", False) or not v.strip() for v in raw):
        return bool(raw)
    return all(_narrow(key, v.strip()) for v in raw)


def _narrow(key: str, value: str) -> bool:
    if key in IP_KEYS:
        try:
            return ipaddress.ip_network(value, strict=False).prefixlen > 0
        except ValueError:
            return False
    if value in EVERYONE:
        return False
    if not {"*", "?"} & set(value):
        return True
    named = value.lower().replace("arn", "").replace("aws", "")
    return sum(c.isalnum() for c in named) >= MIN_LITERAL


def _restricts(statement: dict, keys: frozenset[str]) -> bool:
    """Whether a Condition really narrows the caller: a positive operator that fails for a missing key, one of `keys`,
    and a value that is not everyone."""
    for condition in entries(statement, "condition"):
        for operator, body in condition.items() if isinstance(condition, dict) else ():
            name = str(operator).lower()
            if name.startswith("forallvalues:") or name.endswith("ifexists"):
                continue
            if name.rsplit(":", 1)[-1] not in POSITIVE_OPERATORS or not isinstance(body, dict):
                continue
            if any(str(k).lower() in keys and _acceptable(str(k).lower(), v) for k, v in body.items()):
                return True
    return False


def _proves(statement: dict) -> bool:
    """Whether the Condition makes a cross-account caller prove something: an external id, or MFA."""
    if _restricts(statement, frozenset({"sts:externalid"})):
        return True
    for condition in entries(statement, "condition"):
        for operator, body in condition.items() if isinstance(condition, dict) else ():
            name = str(operator).lower().rsplit(":", 1)[-1]
            for key, value in body.items() if isinstance(body, dict) else ():
                mfa = str(key).lower()
                if (
                    mfa == "aws:multifactorauthpresent" and name == "bool" and "true" in map(str.lower, literals(value))
                ) or (mfa == "aws:multifactorauthage" and name.startswith("numeric")):
                    return True
    return False


def _principals(statement: dict) -> list[Hit]:
    principals = entries(statement, "principal")
    if not principals:
        return []
    keys = _condition_keys(statement)
    assume = any(ASSUME.fullmatch(a) or a in STAR for a in strings_of(statement, "action"))
    if any(_wildcard_principal(p) for p in principals):
        names = NAMES_THE_CALLER if assume else NAMES_THE_CALLER | NAMES_THE_NETWORK
        if keys is None or not _restricts(statement, names):
            return [Hit("iam-trust-wildcard" if assume else "iam-principal-wildcard", BLOCK, "principal")]
        return []
    if assume and any(_foreign_account(p) for p in principals) and not _proves(statement):
        return [Hit("iam-trust-cross-account", ASK, "principal")]
    return []
