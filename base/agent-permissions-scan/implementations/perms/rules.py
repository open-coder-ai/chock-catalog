"""What makes an allow entry, a mode, a flag or an auto-approve rule too broad; pure functions over parsed text."""

from __future__ import annotations

import hashlib
import posixpath
import re

#: Past this a value is keyed by a prefix and a digest of the whole, so a long key stays short and exact.
KEY_TEXT = 160
#: Commands whose prefix wildcard (`curl:*`) hands the agent the network, deletion, privilege or a shell.
RISKY_COMMANDS = frozenset(
    {
        *("curl", "wget", "rm", "sudo", "su", "doas", "sh", "bash", "zsh", "dash", "fish", "eval", "exec", "ssh"),
        *("scp", "nc", "ncat", "netcat", "dd", "chmod", "chown", "mkfs", "xargs", "env", "powershell", "pwsh", "cmd"),
    }
)
SHELL_TOOLS = frozenset({"bash", "shell", "run_shell_command", "execute_bash"})
EDIT_TOOLS = frozenset({"write", "edit", "multiedit", "notebookedit", "write_file", "replace", "edit_file"})
WEB_TOOLS = frozenset({"webfetch", "web_fetch"})
#: Modes (compared as lower-case letters and digits) that approve every action without asking.
DANGER_MODES = frozenset({"bypasspermissions", "yolo", "auto", "autoapprove", "fullauto", "dangerfullaccess"})
TRUE_TEXT = frozenset({"true", "yes", "on", "1"})

_ENTRY = re.compile(r"([A-Za-z0-9_.*-]+)\s*(?:\((.*)\))?", re.DOTALL)
_TRAILING_WILDCARD = re.compile(r"(.*?)(?::\s*\*+|\s+\*+|\*+)\s*", re.DOTALL)
_EVERYTHING = re.compile(r"[*/~.\s:]*")
_ANY_DOMAIN = re.compile(r"(?:domain:)?\s*\*+")
_SLASHED = re.compile(r"/(.*)/[dgimsuvy]*", re.DOTALL)
_REGEX_ALL = frozenset({"", ".*", ".+", r"[\s\S]*", r"[\s\S]+", r"\S*", r"\S+", r"\w*", r"\w+", "[^]*", "[^]+"})
_SKIP_FLAG = re.compile(
    r"--[a-z-]*dangerously-[a-z-]+|--yolo\b|--trust-all-tools\b|--allow-all-tools\b"
    r"|--permission-mode[= ]+['\"]?bypassPermissions|--approval-mode[= ]+['\"]?yolo",
    re.IGNORECASE,
)


def norm(value: object) -> str:
    """Whitespace-collapsed text; long text is a prefix plus a digest of all of it, never a bare prefix."""
    text = " ".join(str(value).split())
    if len(text) <= KEY_TEXT:
        return text
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"{text[:KEY_TEXT]}...#{digest}"


def letters(value: object) -> str:
    """Lower-case letters and digits only: `default_mode`, `Default-Mode` and `defaultMode` read alike."""
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def truthy(value: object) -> bool:
    return (
        value is True
        or (isinstance(value, str) and value.strip().lower() in TRUE_TEXT)
        or (isinstance(value, int) and not isinstance(value, bool) and value == 1)
    )


def skip_flag(text: str) -> str | None:
    """The permission-skipping flag a string carries, as written; None when it carries none."""
    found = _SKIP_FLAG.search(text)
    return found.group(0) if found else None


def broad_entry(entry: str) -> str | None:
    """Why an allow entry grants more than a named, scoped action; None when it is scoped."""
    text = " ".join(entry.split())
    if text in ("*", "**"):
        return "allows every tool"
    if text.lower().startswith("mcp__"):
        return _mcp(text)
    found = _ENTRY.fullmatch(text)
    if not found:
        return None
    judge = _BY_TOOL.get(found.group(1).lower())
    return judge(found.group(2)) if judge else None


def _mcp(text: str) -> str | None:
    if "*" in text:
        return "a wildcard over MCP tools"
    return "every tool of an MCP server" if text.count("__") == 1 else None


def _shell(spec: str | None) -> str | None:
    body = (spec or "").strip().strip("\"'").strip()
    if _EVERYTHING.fullmatch(body):
        return "any shell command"
    if body.startswith("*") or re.match(r":\s*\*", body):
        return "a shell command with a leading wildcard"
    found = _TRAILING_WILDCARD.fullmatch(body)
    if not found:
        return None
    words = found.group(1).split()
    first = posixpath.basename((words or [""])[0]).lower()
    if first in RISKY_COMMANDS or [first, *words[1:2]] == ["git", "push"]:
        return f"a wildcard over {' '.join(words[:2]) if first == 'git' else first}"
    return None


def _edit(spec: str | None) -> str | None:
    body = (spec or "").strip().strip("\"'").strip()
    if _EVERYTHING.fullmatch(body):
        return "writes to any file"
    return "writes outside the project (home or an absolute path)" if body.startswith(("~", "//")) else None


def _web(spec: str | None) -> str | None:
    body = (spec or "").strip().strip("\"'").strip()
    return "fetches any URL" if not body or _ANY_DOMAIN.fullmatch(body) else None


_BY_TOOL = {
    **dict.fromkeys(SHELL_TOOLS, _shell),
    **dict.fromkeys(EDIT_TOOLS, _edit),
    **dict.fromkeys(WEB_TOOLS, _web),
}


def regex_all(pattern: str) -> bool:
    """Whether a `/.../flags` rule matches every command (`/.*/`, `/^.*$/`, `/(?:)/`)."""
    found = _SLASHED.fullmatch(pattern.strip())
    if not found:
        return False
    core = re.sub(r"[\^$()]|\?:|\\b", "", found.group(1))
    return core in _REGEX_ALL


def rule_command(pattern: str) -> str:
    """The command a terminal auto-approve rule names: `curl` for `curl`, `/^curl\\b/` and `/curl .*/`."""
    text = pattern.strip()
    found = _SLASHED.fullmatch(text)
    text = found.group(1) if found else text
    word = re.match(r"[\^(?:]*\s*([A-Za-z0-9_./-]+)", text)
    return posixpath.basename(word.group(1)).lower() if word else ""


def broad_url_or_glob(pattern: str) -> bool:
    """Whether an auto-approve key covers every URL or file: only `*`, `/`, `.`, `:` and a scheme."""
    return bool(re.fullmatch(r"(?:https?:)?[*/.:]*", pattern.strip()))
