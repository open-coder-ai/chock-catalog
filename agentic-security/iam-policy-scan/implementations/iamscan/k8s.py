"""Kubernetes RBAC objects: bindings to cluster-admin and rules that name everything."""

from __future__ import annotations

from typing import NamedTuple

from iamscan.access import entries, literals, strings_of
from iamscan.model import ASK, BLOCK

BINDINGS = {"clusterrolebinding": BLOCK, "rolebinding": ASK}
ROLES = frozenset({"role", "clusterrole"})


class K8sHit(NamedTuple):
    rule: str
    tier: str
    hint: str
    subject: object  # what the finding's id is taken from
    holder: dict  # the mapping whose keys carry the hint's line


def _kind(node: dict) -> str:
    return next(iter(strings_of(node, "kind")), "").lower()


def judge(node: dict) -> list[K8sHit]:
    """Findings for one mapping that is a binding or a role; any other mapping makes none."""
    kind = _kind(node)
    if kind in BINDINGS:
        return _binding(node, BINDINGS[kind])
    if kind in ROLES:
        return [hit for rule in _rules(node) for hit in _rule(kind, rule)]
    return []


def _binding(node: dict, tier: str) -> list[K8sHit]:
    refs = [r for r in entries(node, "roleref") if isinstance(r, dict)]
    if any("cluster-admin" in [n.lower() for n in strings_of(r, "name")] for r in refs):
        return [
            K8sHit(
                "k8s-cluster-admin-binding",
                tier,
                "cluster-admin",
                [_kind(node), refs, entries(node, "subjects")],
                refs[0],
            )
        ]
    return []


def _rules(node: dict) -> list[dict]:
    return [r for group in entries(node, "rules") if isinstance(group, list) for r in group if isinstance(r, dict)]


def _rule(kind: str, rule: dict) -> list[K8sHit]:
    wild = {name: "*" in literals(entries(rule, name)) for name in ("verbs", "resources", "apigroups")}
    if wild["verbs"] or wild["resources"]:
        return [K8sHit("k8s-rbac-wildcard", BLOCK, "verbs" if wild["verbs"] else "resources", [kind, rule], rule)]
    if wild["apigroups"]:
        return [K8sHit("k8s-rbac-wildcard", ASK, "apiGroups", [kind, rule], rule)]
    return []
