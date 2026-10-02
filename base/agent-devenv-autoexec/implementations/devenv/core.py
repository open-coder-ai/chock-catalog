"""Findings, the rule table and the command and path tests every surface shares."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from typing import NamedTuple

BLOCK, ASK = "block", "ask"

#: rule id -> (pack, CWE). The roadmap's ids (NP03, agent-devenv-autoexec bundle), plus four this
#: build adds: extension recommendations, agent spawn flags, symlinks and unparseable configs.
RULES = {
    "dev-claude-hooks": ("agent-config", 94),
    "dev-claude-env-override": ("agent-config", 94),
    "dev-mcp-autoapprove": ("agent-config", 862),
    "dev-cross-reference": ("agent-config", 94),
    "dev-agent-spawn": ("agent-config", 250),
    "dev-vscode-folderopen": ("vscode", 94),
    "dev-vscode-autoapprove": ("vscode", 862),
    "dev-vscode-trust-off": ("vscode", 862),
    "dev-exec-path-settings": ("vscode", 94),
    "dev-vscode-extension-recs": ("vscode", 829),
    "dev-devcontainer-init": ("devcontainer", 94),
    "dev-shell-toolchain": ("shell-toolchain", 94),
    "dev-hook-launchers": ("shell-toolchain", 94),
    "dev-gitconfig-exec": ("git", 94),
    "dev-gitattributes-filter": ("git", 94),
    "dev-gitmodules-untrusted": ("git", 22),
    "dev-symlink-escape": ("git", 59),
    "dev-unparseable": ("agent-config", 20),
}

#: Past this a value is keyed by a prefix and a digest of the whole, so a long key stays short and exact.
KEY_TEXT = 160
#: Longer than any real command line; past it a command is refused rather than searched.
MAX_COMMAND = 8192


class Finding(NamedTuple):
    rule: str
    line: int
    detail: str
    message: str
    severity: str


class Collector:
    """The findings of one file. `detail` is the key: where (a key path) and what (the normalized value)."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = text.split("\n")
        self.found: list[Finding] = []
        #: Each command a config makes a tool run: (where, command, line), for the cross-reference check.
        self.commands: list[tuple[str, str, int]] = []

    def add(self, rule: str, detail: str, message: str, *, severity: str = BLOCK, line: int | None = None) -> None:
        self.found.append(Finding(rule, line or 1, detail, message, severity))

    def line_of(self, *needles: str) -> int:
        """The first line holding the last needle after the earlier ones, 1-based; 1 when absent."""
        at = 0
        for needle in needles:
            found = self.text.find(needle, at)
            if found < 0:
                break
            at = found
        return self.text.count("\n", 0, at) + 1


def norm(value: object) -> str:
    """Whitespace-collapsed text; long text is a prefix plus a digest of all of it, never a bare prefix."""
    text = " ".join(str(value).split())
    if len(text) <= KEY_TEXT:
        return text
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"{text[:KEY_TEXT]}...#{digest}"


def blank_strings(text: str) -> str:
    """The text with every string's contents removed in one pass, line breaks kept so lines still line up.

    `\"\"\"...\"\"\"` and `\'\'\'...\'\'\'` span lines (TOML, Python); other quotes end at the line's end,
    and a quote left open blanks the rest of that line. Nothing inside a value can read as a comment.
    """
    out: list[str] = []
    quote = ""
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if quote:
            if char == "\n":
                out.append(char)
                quote = quote if len(quote) == len('"""') else ""
            elif char == "\\" and quote[0] == '"':
                index += text[index + 1 : index + 2] != "\n"
            elif text.startswith(quote, index):
                index += len(quote) - 1
                quote = ""
        elif char in "\"'":
            quote = char * 3 if text.startswith(char * 3, index) else char
            index += len(quote) - 1
        else:
            out.append(char)
        index += 1
    return "".join(out)


def digest(value: object) -> str:
    """A short digest of a parsed value, so a key changes whenever anything inside it does."""
    text = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def walk(value: object, path: tuple = ()) -> Iterator[tuple[tuple, object]]:
    """Every leaf of a parsed JSON/TOML value with its key path; an empty container is a leaf."""
    if isinstance(value, dict) and value:
        for key, item in value.items():
            yield from walk(item, (*path, key))
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            yield from walk(item, (*path, index))
    else:
        yield path, value


def trim(path: tuple) -> tuple:
    """A path without its trailing list indexes: `tasks.a.run` for `tasks.a.run.0`."""
    while path and isinstance(path[-1], int):
        path = path[:-1]
    return path


def key_of(path: tuple) -> str:
    """The last key of a path, past any list indexes."""
    kept = trim(path)
    return str(kept[-1]) if kept else ""


def dotted(path: tuple) -> str:
    return ".".join(str(part) for part in path) or "<root>"


def strings(value: object) -> list[str]:
    """A command value as its strings: a string, the strings of a list, or the values of an object."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [" ".join(str(item) for item in value)] if value else []
    if isinstance(value, dict):
        return [text for item in value.values() for text in strings(item)]
    return []


_FETCH = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|aria2c|fetch|lwp-download|lynx|httpie|xh)"
_INTERP = r"(?:(?:ba|z|da|k|fi|c|tc|a)?sh|python[0-9.]*|node|deno|bun|perl|ruby|php|pwsh|powershell|iex|invoke-expression|source|\.)"
_PIPE_TO_INTERP = re.compile(
    rf"(?i)\b{_FETCH}\b[^|\n]{{0,1000}}\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:\S*[/\\])?{_INTERP}(?![\w.-])"
)
_SUBST_FETCH = re.compile(rf"(?i)(?:\$\(|`|<\(|\(\s*)\s*(?:\S*[/\\])?{_FETCH}\b")
_EVAL_FETCH = re.compile(rf"(?i)\b(?:eval|iex|invoke-expression)\b[^\n]{{0,1000}}?\b{_FETCH}\b")
_ENCODED = re.compile(
    r"(?i)(?:\b(?:pwsh|powershell)(?:\.exe)?\b[^\n]{0,1000}?\s-e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{12,}"
    r"|\bbase64\s+(?:-d|--decode|-D)\b|\bfrombase64string\b|\bcertutil\b[^\n]{0,1000}?-decode"
    r"|\b(?:node|deno|bun)\s+(?:-e|--eval|-p|--print)\b|\bpython[0-9.]*\s+-c\b|\b(?:perl|ruby)\s+-e\b"
    r"|[A-Za-z0-9+/]{80,}={0,2})"
)
_NETWORK = re.compile(
    rf"(?i)\b(?:{_FETCH}|nc|ncat|netcat|socat|telnet|scp|sftp|ftp|tftp|rsync|ssh)\b|\b(?:https?|ftp)://|/dev/tcp/"
)


def risky(command: str) -> str | None:
    """Why a command fetches and runs, or runs an encoded or inline payload; None when it does neither."""
    if len(command) > MAX_COMMAND:
        # Not searched: the time would grow with its length, so it is refused instead.
        return "is too long to judge"
    if _PIPE_TO_INTERP.search(command) or _SUBST_FETCH.search(command) or _EVAL_FETCH.search(command):
        return "fetches and runs code"
    if _ENCODED.search(command):
        return "runs an encoded or inline program"
    return None


def network(command: str) -> bool:
    return bool(_NETWORK.search(command))


#: Folders package managers and virtualenv tools create, where a configured tool path is expected.
TOOL_DIRS = frozenset({".venv", "venv", "node_modules", ".tox", ".nox", ".pixi", ".conda", ".yarn", "vendor"})
_VARIABLE_ROOT = re.compile(r"(?i)^\$\{(?:workspacefolder|workspaceroot|cwd|fileworkspacefolder|relativefile)[^}]*\}")
_SYSTEM_ROOT = re.compile(r"(?i)^(?:/|~|\$\{(?:env:|userhome|pathseparator)|\$[A-Za-z_]|%|[a-z]:[\\/]|\\\\)")


def into_repo(value: str) -> str | None:
    """`block` for a path into the repository, `ask` for one under a tool-created folder, None otherwise.

    Into the repository: `${workspaceFolder}...` or a relative path with a separator; a bare program
    name (found on PATH) and absolute or home paths are not.
    """
    text = value.strip().strip("'\"")
    if _VARIABLE_ROOT.match(text):
        rest = _VARIABLE_ROOT.sub("", text)
    elif _SYSTEM_ROOT.match(text) or not re.search(r"[\\/]", text):
        return None
    else:
        rest = text
    first = next((part for part in re.split(r"[\\/]+", rest) if part and part != "."), "")
    return ASK if first.lower() in TOOL_DIRS else BLOCK
