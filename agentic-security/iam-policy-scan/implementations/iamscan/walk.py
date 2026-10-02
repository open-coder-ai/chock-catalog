"""Walk a parsed document for grants: every mapping is judged, wherever it sits, and JSON in a string is opened."""

from __future__ import annotations

import re
from typing import NamedTuple

from chock_scan import jsonc

from iamscan import aws, azure, k8s
from iamscan.model import BLOCK, Finding, signature

MAX_DEPTH = 200
EMBED_DEPTH = 3
#: Keys a finding is placed by in a file that records no lines (JSON): counted in document order.
LOCATABLE = frozenset(
    {
        "action",
        "notaction",
        "principal",
        "resource",
        "notresource",
        "notprincipal",
        "verbs",
        "resources",
        "roledefinitionid",
    }
)
LOOKS_LIKE_POLICY = re.compile(r'(?is)^\s*\{.*"(?:Statement|Effect|rules|kind)"')
#: Keys whose repeated occurrence in one mapping hides a value from one of the loaders that read it.
GUARDED_KEYS = frozenset(
    {"effect", "action", "notaction", "resource", "notresource", "principal", "notprincipal", "condition", "statement",
     "kind", "rules", "verbs", "resources", "apigroups", "roleref", "subjects", "properties", "type", "scope"}
)  # fmt: skip


class Spot(NamedTuple):
    """Where a finding is: its line, the key it is about, and every line a waiver beside it may sit on."""

    line: int
    hint: str
    anchors: tuple[int, ...]
    nth: int = -1


class Scan:
    """Findings for one file; `base` is the line a value without its own line is reported at, `span` its extent."""

    def __init__(self, path: str, *, subscription_deployment: bool = False) -> None:
        self.path = path
        self.found: list[Finding] = []
        self.subscription_deployment = subscription_deployment
        self._ticks: dict[str, int] = {}
        self._counting = True

    def add(self, rule: str, tier: str, subject: object, spot: Spot) -> None:
        self.found.append(
            Finding(rule, tier, self.path, spot.line, signature(subject), spot.anchors, spot.hint, spot.nth)
        )

    def unreadable(self, why: str, line: int = 1) -> None:
        self.found.append(Finding("iam-unreadable", BLOCK, self.path, line, signature(why), (line,)))

    def duplicate(self, name: str, line: int) -> None:
        if name.lower() in GUARDED_KEYS:
            self.found.append(
                Finding("iam-duplicate-key", BLOCK, self.path, line, signature(name.lower()), (line,), name)
            )

    def walk(
        self, node: object, base: int = 1, span: tuple[int, int] | None = None, depth: int = 0, embed: int = 0
    ) -> None:
        if depth > MAX_DEPTH:
            msg = "nested deeper than the gate reads"
            raise ValueError(msg)
        line = getattr(node, "line", 0) or base
        if isinstance(node, dict):
            self._mapping(node, line, span)
            for child in node.values():
                self.walk(child, line, span, depth + 1, embed)
        elif isinstance(node, list | tuple):
            for child in node:
                self.walk(child, line, span, depth + 1, embed)
        elif isinstance(node, str):
            self.embedded(node, line, span, embed)

    def _anchors(self, *lines: int, span: tuple[int, int] | None) -> tuple[int, ...]:
        return tuple(sorted({*lines, *(range(span[0], span[1] + 1) if span else ())}))

    def _tick(self, node: dict) -> dict[str, int]:
        """Number each locatable key of this mapping among all such keys seen so far in the file, in document order."""
        if not self._counting:
            return {}
        out = {}
        for key in node:
            name = key.lower() if isinstance(key, str) else ""
            if name in LOCATABLE:
                out[name] = self._ticks[name] = self._ticks.get(name, -1) + 1
        return out

    def _mapping(self, node: dict, line: int, span: tuple[int, int] | None) -> None:
        nth = self._tick(node)
        for hit in aws.judge(node):
            at = _hint_line(getattr(node, "keylines", {}), hit.hint, line)
            self.add(
                hit.rule, hit.tier, node, Spot(at, hit.hint, self._anchors(at, line, span=span), nth.get(hit.hint, -1))
            )
        for k8s_hit in k8s.judge(node):
            holder = k8s_hit.holder
            at = _hint_line(getattr(holder, "keylines", {}), k8s_hit.hint, getattr(holder, "line", 0) or line)
            self.add(
                k8s_hit.rule,
                k8s_hit.tier,
                k8s_hit.subject,
                Spot(at, k8s_hit.hint, self._anchors(at, line, span=span), nth.get(k8s_hit.hint.lower(), -1)),
            )
        if azure.arm_assignment(node, subscription_deployment=self.subscription_deployment):
            self.add(
                "azure-subscription-owner",
                BLOCK,
                node,
                Spot(line, "roleDefinitionId", self._anchors(line, span=span), nth.get("roledefinitionid", -1)),
            )

    def embedded(self, text: str, line: int, span: tuple[int, int] | None, embed: int) -> None:
        """Open JSON held in a string; `embed` counts strings opened inside strings, not how deep the file nests."""
        if embed >= EMBED_DEPTH or not LOOKS_LIKE_POLICY.match(text):
            return
        try:
            document = jsonc.loads(text)
        except (jsonc.JsoncError, RecursionError):
            self.unreadable("a JSON policy inside a string cannot be read", line)
            return
        for dup in document.duplicates:
            self.duplicate(str(dup.path[-1]), line)
        counting, self._counting = self._counting, False
        try:
            self.walk(document.value, line, span, 0, embed + 1)
        finally:
            self._counting = counting


def _hint_line(keylines: dict, hint: str, fallback: int) -> int:
    """The line of the key a finding is about when the file records lines (YAML), else the mapping's line."""
    for key, at in keylines.items():
        if isinstance(key, str) and key.lower() == hint.lower():
            return at
    return fallback
