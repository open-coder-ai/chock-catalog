"""MCP and agent client configs read structurally: JSON and TOML parsed, never matched line by line.

A pretty-printed `args` array puts the package on a different line from `npx`, so a line regex
cannot tell what a server launches. Servers come out of the parsed document instead, and a
finding is placed on the line where the server's name or the offending value sits.
"""

from __future__ import annotations

import json
import re
import shlex
import tomllib
from typing import Any, NamedTuple

from agentic_gate.model import FileText

_SERVER_TABLES = ("mcpServers", "mcp_servers", "servers")
_NPX_VALUES = frozenset({"--registry", "--cache", "--userconfig", "--prefix", "-w", "--workspace"})
_UVX_VALUES = frozenset(
    {"--with", "-w", "--with-requirements", "--with-editable", "-p", "--python", "--index", "--index-url", "-i"}
    | {"--extra-index-url", "--default-index", "-c", "--constraints", "--env-file", "--directory"}
)
#: per launcher: the flags that carry the package spec, and the other flags that take a value.
_FLAGS = {
    "npx": (frozenset({"-p", "--package"}), _NPX_VALUES),
    "bunx": (frozenset({"-p", "--package"}), _NPX_VALUES),
    "uvx": (frozenset({"--from"}), _UVX_VALUES),
    "pipx": (frozenset({"--spec"}), frozenset({"--python", "--index-url", "--pip-args"})),
}
_LOCAL = re.compile(r"^(?:[./~]|file:|[A-Za-z]:[\\/])")
_URL = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|git\+|github:|gitlab:|bitbucket:)", re.IGNORECASE)
_NPM_PINNED = re.compile(r"@v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?$")
_PY_PINNED = re.compile(r"(?:===?|@)v?\d+(?:\.\d+)*(?:[-+.\w]*)?$")


class Server(NamedTuple):
    name: str
    body: dict[str, Any]


class Launch(NamedTuple):
    """What a launcher command runs: the tool, the package spec it fetches, and whether it is git."""

    tool: str
    spec: str


def _document(text: FileText) -> Any:
    try:
        if text.kind == "toml":
            return tomllib.loads(text.text)
        body = "\n".join(line for line in text.lines if not line.lstrip().startswith("//"))
        return json.loads(body)
    except (ValueError, RecursionError):
        return None


def _tables(node: Any) -> list[dict[str, Any]]:
    """Every server table (name -> server) anywhere in a document."""
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _SERVER_TABLES and isinstance(value, dict):
                found.append(value)
            found += _tables(value)
    elif isinstance(node, list):
        for item in node:
            found += _tables(item)
    return found


def servers(text: FileText) -> list[Server]:
    """The servers a config declares, in document order. Empty for a file that does not parse."""
    if not text.is_mcp_config:
        return []
    return [
        Server(str(name), body)
        for table in _tables(_document(text))
        for name, body in table.items()
        if isinstance(body, dict)
    ]


def argv(server: Server) -> list[str]:
    """The command and its arguments as one vector, whether written as a string or a list."""
    command = server.body.get("command")
    head = shlex.split(command) if isinstance(command, str) else [str(c) for c in command or []]
    args = server.body.get("args")
    return head + [str(a) for a in args] if isinstance(args, list) else head


def line_for(text: FileText, server: Server, needle: str) -> int:
    """The line of `needle` at or after the server's own name, else the server's line, else 1."""
    lines = text.lines
    named = re.compile(rf"[\"'.\[]{re.escape(server.name)}[\"'\]]")
    start = next((i for i, line in enumerate(lines) if named.search(line)), 0)
    return next((i + 1 for i in range(start, len(lines)) if needle in lines[i]), start + 1)


def _json_end(lines: list[str], start: int) -> int:
    """The line where the object opened on `start` closes."""
    depth = 0
    for index in range(start, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        if depth <= 0:
            return index
    return len(lines) - 1


def _toml_end(lines: list[str], start: int, name: str) -> int:
    """The line before the next table that is not one of this server's own."""
    for index in range(start + 1, len(lines)):
        row = lines[index].lstrip()
        if row.startswith("[") and name not in row:
            return index - 1
    return len(lines) - 1


def block(text: FileText, server: Server) -> tuple[int, ...]:
    """The lines of the server's whole entry: its braces in JSON, its table and sub-tables in TOML."""
    lines = text.lines
    named = re.compile(rf"[\"'.\[]{re.escape(server.name)}[\"'\]]")
    start = next((i for i, line in enumerate(lines) if named.search(line)), 0)
    end = _toml_end(lines, start, server.name) if text.kind == "toml" else _json_end(lines, start)
    return tuple(range(start + 1, end + 2))


def _split(args: list[str], spec_flags: frozenset[str], value_flags: frozenset[str]) -> tuple[str | None, list[str]]:
    """The package spec a `--from`-style flag names, and the positional arguments."""
    spec: str | None = None
    positional: list[str] = []
    pending = ""
    for arg in args:
        name, equals, value = arg.partition("=")
        if pending:
            spec = arg if pending in spec_flags else spec
            pending = ""
        elif name in spec_flags | value_flags:
            spec = value if equals and name in spec_flags else spec
            pending = "" if equals else name
        elif not arg.startswith("-"):
            positional.append(arg)
    return spec, positional


def launch(command: list[str]) -> Launch | None:
    """The package a `npx`, `bunx`, `uvx` or `pipx run` command fetches, or None if it is not one."""
    tool = re.sub(r"\.(cmd|exe)$", "", command[0].replace("\\", "/").rsplit("/", 1)[-1].lower()) if command else ""
    if tool not in _FLAGS:
        return None
    args = command[1:]
    if tool == "pipx":
        args = args[1:] if args[:1] == ["run"] else []
    spec, positional = _split(args, *_FLAGS[tool])
    spec = spec or (positional[0] if positional else None)
    return Launch(tool, spec) if spec else None


def is_pinned(found: Launch) -> bool:
    """Whether the spec names an exact version: `pkg@1.2.3` for npm, `pkg==1.2.3` or `pkg@1.2.3` for Python."""
    pattern = _NPM_PINNED if found.tool in ("npx", "bunx") else _PY_PINNED
    return bool(pattern.search(found.spec))


def is_fetched_by_name(found: Launch) -> bool:
    """A registry package, as opposed to a local path or a URL (git specs have their own rule)."""
    return not (_LOCAL.match(found.spec) or _URL.match(found.spec))
