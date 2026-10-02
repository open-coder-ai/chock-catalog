"""Azure role assignments of Owner or Contributor at subscription scope or broader: ARM JSON, Terraform, Bicep."""

from __future__ import annotations

import re

from iamscan.access import entries, literals

OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_IDS = (OWNER, CONTRIBUTOR)
ROLE_NAMES = frozenset({"owner", "contributor"})
ASSIGNMENT = "microsoft.authorization/roleassignments"
INTERPOLATION = r"\$\{(?:[^{}]|\{[^{}]*\})*\}"
#: A scope at the subscription or above: the subscription itself, a management group, the tenant, however spelled.
SUBSCRIPTION_SCOPE = re.compile(
    rf"(?i)/subscriptions/(?:[\w-]|{INTERPOLATION}|\{{[^{{}}]*\}})+/?"
    r"|\[?(?:subscription|managementGroup|tenant)\([^()\n]*\)(?:\.id)?\]?"
    rf"|/providers/Microsoft\.Management/managementGroups/(?:[^/\s]|{INTERPOLATION})+/?|/"
    r"|data\.azurerm_(?:subscription|management_group)\.\w+(?:\[\d+\])?\.id"
    r"|\[?(?:concat|format)\(\s*['\"]/subscriptions/[^\n]*\)\]?|\[?tenantResourceId\([^\n]*\)\]?"
)
#: Deployment templates whose resources have no scope but the subscription, a management group or the tenant.
BROAD_SCHEMA = re.compile(r"(?i)(?:subscription|managementgroup|tenant)deploymenttemplate")
BICEP_RESOURCE = re.compile(r"(?im)^[ \t]*resource\s+\w+\s+'Microsoft\.Authorization/roleAssignments@[^']*'\s*=")
BICEP_TARGET = re.compile(r"(?m)^\s*targetScope\s*=\s*'(?:subscription|managementGroup|tenant)'")
#: A body read past this is not read: one unbalanced brace must not make every match rescan the rest of the file.
MAX_BODY = 20_000
MAX_BICEP_RESOURCES = 500


def names_privileged_role(text: str) -> bool:
    low = text.lower()
    return any(guid in low for guid in ROLE_IDS)


def at_subscription(scope: str) -> bool:
    """Subscription scope or broader, written plainly or as one `${...}` template."""
    text = scope.strip().strip("\"'")
    wrapped = re.fullmatch(r"\$\{(.*)\}", text, re.S)
    return bool(SUBSCRIPTION_SCOPE.fullmatch(wrapped.group(1).strip() if wrapped else text))


def arm_assignment(node: dict, *, subscription_deployment: bool) -> bool:
    """Whether an ARM resource is an Owner or Contributor assignment at subscription scope or broader."""
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
    """Lines of Owner or Contributor assignments in a Bicep file that deploy at subscription scope or broader.

    More than MAX_BICEP_RESOURCES assignments in one file is reported as a single line-one finding by the caller.
    """
    broad = BICEP_TARGET.search(text) is not None
    found = []
    for match in list(BICEP_RESOURCE.finditer(text))[: MAX_BICEP_RESOURCES + 1]:
        body = _body(text, match.end())
        if not names_privileged_role(body):
            continue
        scoped = _top_scope(body)
        if at_subscription(scoped) if scoped is not None else broad:
            found.append(text.count("\n", 0, match.start()) + 1)
    return found


def _body(text: str, start: int) -> str:
    """The `{...}` of a resource that begins at the first `{` after `start`, whatever the `[for ...]` or `if (...)` before it."""
    window = text[start : start + MAX_BODY]
    opened = window.find("{")
    if opened < 0:
        return ""
    depth = 0
    for match in re.finditer(r"'''.*?'''|'(?:[^'\\\n]|\\.)*'|//[^\n]*|/\*.*?\*/|[{}]", window[opened:], re.S):
        depth += {"{": 1, "}": -1}.get(match.group(), 0)
        if not depth:
            return window[opened : opened + match.end()]
    return window[opened:]


def _top_scope(body: str) -> str | None:
    """The value of the resource's own `scope:` property: not one in a comment, a string or a nested object."""
    depth, out, line = 0, [], []
    for token in re.finditer(r"'''.*?'''|'(?:[^'\\\n]|\\.)*'|//[^\n]*|/\*.*?\*/|[{}\n]|[^{}\n'/]+|.", body, re.S):
        text = token.group()
        if text == "\n":
            out.append((depth, "".join(line)))
            line = []
        elif text in "{}":
            depth += 1 if text == "{" else -1
        elif not text.startswith(("//", "/*", "'''")):
            line.append(text)
    out.append((depth, "".join(line)))
    for at, content in out:
        match = re.match(r"\s*scope\s*:\s*(.+)$", content)
        if match and at == 1:
            return match.group(1)
    return None
