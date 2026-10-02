"""Walk a parsed agent config and report each grant, mode, flag or auto-approve rule that widens what the agent may do."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from typing import NamedTuple

from perms import rules

ALLOW, DENY, MODE, FLAG, VSCODE, SKIP = (
    "ap-allow-broad",
    "ap-deny-removed",
    "ap-mode-bypass",
    "ap-auto-approve",
    "ap-vscode-autoapprove",
    "ap-skip-flag",
)
CODEX = "ap-codex-never-danger"
ALLOW_KEYS = frozenset({"allow", "allowedtools", "allowed", "alwaysallow", "autoapprove", "tools"})
#: Key names end in one of these (`claudeCode.initialPermissionMode`, `chat.tools.global.autoApprove`).
MODE_ENDINGS = ("defaultmode", "permissionmode", "approvalmode")
FLAG_KEYS = frozenset({"yolo", "yesalways", "trustalltools", "trustall"})
FLAG_ENDINGS = ("autoapprove", "autoaccept", "dangerouslyskippermissions")
#: Where each surface keeps the entries that forbid an action; a shrinking list there is a finding.
DENY_PATHS = {
    "claude": (("permissions", "deny"),),
    "cursor": (("permissions", "deny"),),
    "gemini": (("tools", "exclude"), ("excludeTools",)),
    "continue": (("exclude",), ("permissions", "exclude")),
}
#: Keys that hold what is forbidden or asked; their strings are not grants, and a flag named there is a ban.
QUIET_KEYS = frozenset({"deny", "ask", "exclude", "excludetools", "disallowedtools"})
#: In VS Code settings only the keys of an agent extension count (`editor.defaultMode` is no permission mode).
VSCODE_PREFIXES = ("claudecode", "chat", "github", "cline", "roo", "cursor", "continue")
OPENCODE_TOOLS = frozenset({"bash", "edit", "write", "webfetch", "external_directory", "*"})


class Hit(NamedTuple):
    """One finding: the rule, where (key path, no list indexes) and the normalized value, and what to say."""

    rule: str
    path: str
    value: str
    why: str


def dotted(path: tuple) -> str:
    return ".".join(str(part) for part in path) or "<root>"


def entries(value: object) -> list[str]:
    """The strings of a list, or the string itself; nothing else."""
    if isinstance(value, str):
        return [value]
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def hits(tree: object, surface: str, hidden: tuple = ()) -> list[Hit]:
    """Every widening in the tree, one per occurrence, then those only a repeated key's hidden values add."""
    found: list[Hit] = []
    _walk(tree, (), surface, found)
    if surface == "codex":
        found.extend(_codex(tree))
    extra: list[Hit] = []
    for path, value in hidden:
        keys = tuple(part for part in path if isinstance(part, str))
        extra.extend(_key(keys[-1], value, keys, surface))
        _walk(value, keys, surface, extra)
    seen = set(found)
    return found + [hit for hit in dict.fromkeys(extra) if hit not in seen]


def denies(tree: object, surface: str) -> Counter:
    """Each deny entry at the surface's deny paths, counted, so a removed copy of a repeated entry shows."""
    out: Counter = Counter()
    for path in DENY_PATHS.get(surface, ()):
        node = tree
        for step in path:
            node = node.get(step) if isinstance(node, dict) else None
        out.update((dotted(path), rules.norm(item)) for item in entries(node))
    if surface == "opencode" and isinstance(tree, dict):
        out.update(_opencode_denies(tree.get("permission")))
    return out


def _opencode_denies(permission: object) -> list[tuple[str, str]]:
    """opencode keeps a deny as a verdict: `permission.<tool>` set to deny, or a pattern under it set to deny."""
    if not isinstance(permission, dict):
        return []
    out = [("permission", str(tool)) for tool, verdict in permission.items() if verdict == "deny"]
    for tool, setting in permission.items():
        if isinstance(setting, dict):
            out += [(f"permission.{tool}", str(pattern)) for pattern, verdict in setting.items() if verdict == "deny"]
    return out


def _walk(node: object, path: tuple, surface: str, out: list[Hit]) -> None:
    if isinstance(node, str):
        if flag := rules.skip_flag(node):
            out.append(Hit(SKIP, dotted(path), flag, "a permission-skipping flag is committed in config"))
    elif isinstance(node, list):
        for item in node:
            _walk(item, path, surface, out)
    elif isinstance(node, dict):
        for key, value in node.items():
            here = (*path, key)
            out.extend(_key(str(key), value, here, surface))
            if rules.letters(key) not in QUIET_KEYS:
                _walk(value, here, surface, out)


def _key(key: str, value: object, path: tuple, surface: str) -> Iterator[Hit]:
    name = rules.letters(key)
    where = dotted(path)
    if name in ALLOW_KEYS and not isinstance(value, bool):
        for entry in entries(value):
            if why := rules.broad_entry(entry):
                yield Hit(ALLOW, where, rules.norm(entry), why)
    if surface == "vscode" and not name.startswith(VSCODE_PREFIXES):
        return
    if name.endswith(MODE_ENDINGS) and isinstance(value, str) and rules.letters(value) in rules.DANGER_MODES:
        yield Hit(MODE, where, rules.norm(value), "the default mode approves every action without asking")
    if (name in FLAG_KEYS or name.endswith(FLAG_ENDINGS)) and rules.truthy(value):
        yield Hit(FLAG, where, "true", "an auto-approve or trust-everything switch is on")
    if name.endswith("autoapprove") and isinstance(value, dict):
        yield from _approvals(value, where)
    yield from _surface(name, value, where, surface)


def _approvals(rule_map: dict, where: str) -> Iterator[Hit]:
    """Auto-approve rules that cover every command, URL or file, or a risky command."""
    for pattern, verdict in rule_map.items():
        approved = rules.truthy(verdict) or (isinstance(verdict, dict) and rules.truthy(verdict.get("approve")))
        if approved and (why := rules.approval_reach(str(pattern))):
            yield Hit(VSCODE, where, rules.norm(pattern), why)


def _surface(name: str, value: object, where: str, surface: str) -> Iterator[Hit]:
    if surface == "gemini":
        if name == "trust" and rules.truthy(value):
            yield Hit(FLAG, where, "true", "a server's tools are trusted without asking")
        if name == "foldertrust" and isinstance(value, dict) and value.get("enabled") is False:
            yield Hit(FLAG, f"{where}.enabled", "false", "folder trust is off")
    if surface == "opencode" and name == "permission":
        yield from _opencode(value, where)


def _opencode(value: object, where: str) -> Iterator[Hit]:
    if isinstance(value, str):
        value = {"*": value}
    for tool, setting in (value if isinstance(value, dict) else {}).items():
        wide = setting.get("*") if isinstance(setting, dict) else setting
        if str(tool).lower() in OPENCODE_TOOLS and wide == "allow":
            yield Hit(ALLOW, where, f"{tool}=allow", "a tool is allowed without asking")


def _codex(tree: object) -> list[Hit]:
    """`approval_policy = never` with `sandbox_mode = danger-full-access` in one effective profile."""
    if not isinstance(tree, dict):
        return []
    profiles = tree.get("profiles")
    tables = [("<root>", tree)] + [
        (f"profiles.{name}", {**tree, **table})
        for name, table in (profiles if isinstance(profiles, dict) else {}).items()
        if isinstance(table, dict)
    ]
    return [
        Hit(CODEX, where, "never+danger-full-access", "no approval and no sandbox: the agent runs anything unasked")
        for where, table in tables
        if rules.letters(table.get("approval_policy")) == "never"
        and rules.letters(table.get("sandbox_mode")) == "dangerfullaccess"
    ]
