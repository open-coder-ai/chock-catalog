"""Azure role assignments of Owner or Contributor at subscription scope: ARM JSON, Terraform and Bicep."""

from __future__ import annotations

import re

from iamscan.access import entries, literals

OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_IDS = (OWNER, CONTRIBUTOR)
ROLE_NAMES = frozenset({"owner", "contributor"})
ASSIGNMENT = "microsoft.authorization/roleassignments"
SUBSCRIPTION_SCOPE = re.compile(
    r"(?i)/subscriptions/(?:[\w-]+|\$\{[^}]*\}|\{[^}]*\})/?|\[?subscription\(\)(?:\.id)?\]?"
    r"|/providers/Microsoft\.Management/managementGroups/[^/\s]+/?|/"
    r"|data\.azurerm_subscription\.\w+\.id"
)
SUBSCRIPTION_SCHEMA = "subscriptiondeploymenttemplate"
BICEP_RESOURCE = re.compile(
    r"(?i)^[ \t]*resource\s+\w+\s+'Microsoft\.Authorization/roleAssignments@[^']*'\s*=\s*"
    r"(?:\[[^\n]*?:\s*|if\s*\([^\n]*?\)\s*)?\{",
    re.M,
)
#: A body read past this is not read: one unbalanced brace must not make every match rescan the rest of the file.
MAX_BODY = 20_000


def names_privileged_role(text: str) -> bool:
    low = text.lower()
    return any(guid in low for guid in ROLE_IDS)


def at_subscription(scope: str) -> bool:
    """Subscription scope, or broader (a management group, the tenant), written plainly or as one `${...}` template."""
    text = scope.strip().strip("\"'")
    wrapped = re.fullmatch(r"\$\{(.*)\}", text, re.S)
    return bool(SUBSCRIPTION_SCOPE.fullmatch(wrapped.group(1).strip() if wrapped else text))


def arm_assignment(node: dict, *, subscription_deployment: bool) -> bool:
    """Whether an ARM resource is an Owner or Contributor assignment at subscription scope."""
    if not any(t.lower().startswith(ASSIGNMENT) for t in literals(entries(node, "type"))):
        return False
    props = [p for p in entries(node, "properties") if isinstance(p, dict)]
    role = " ".join(literals([v for p in props for v in entries(p, "roledefinitionid")]))
    scopes = literals([*entries(node, "scope"), *(v for p in props for v in entries(p, "scope"))])
    if not names_privileged_role(role):
        return False
    return any(at_subscription(s) for s in scopes) if scopes else subscription_deployment


def terraform_assignment(attrs: dict[str, tuple[str, object]]) -> bool:
    """`attrs` maps an azurerm_role_assignment's attribute to (source text, literal value)."""
    name = attrs.get("role_definition_name", ("", ""))[1]
    role = (isinstance(name, str) and name.lower() in ROLE_NAMES) or names_privileged_role(
        attrs.get("role_definition_id", ("", ""))[0]
    )
    scope = attrs.get("scope", ("", ""))[0]
    return role and bool(scope) and at_subscription(scope)


def bicep_assignments(text: str) -> list[int]:
    """Lines of Owner or Contributor assignments in a Bicep file that deploys at subscription scope."""
    subscription = re.search(r"(?m)^\s*targetScope\s*=\s*'subscription'", text) is not None
    found = []
    for match in BICEP_RESOURCE.finditer(text):
        body = _balanced(text, match.end() - 1)
        scoped = re.search(r"(?m)^\s*scope\s*:\s*(.+)$", body)
        if not names_privileged_role(body):
            continue
        if at_subscription(scoped.group(1)) if scoped else subscription:
            found.append(text.count("\n", 0, match.start()) + 1)
    return found


def _balanced(text: str, start: int) -> str:
    """The text from the `{` at `start` to its matching `}`, strings and comments ignored; to MAX_BODY if unmatched."""
    depth = 0
    window = text[start : start + MAX_BODY]
    for match in re.finditer(r"'(?:[^'\\\n]|\\.)*'|//[^\n]*|/\*.*?\*/|[{}]", window, re.S):
        depth += {"{": 1, "}": -1}.get(match.group(), 0)
        if not depth:
            return window[: match.end()]
    return window
