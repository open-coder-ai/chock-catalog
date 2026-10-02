"""Git files that make git run programs or fetch from untrusted places: .gitmodules, .gitattributes, gitconfig."""

from __future__ import annotations

import re

from devenv.core import Collector, norm
from devenv.parse import UnreadableError

MODULES, ATTRIBUTES, CONFIG = "dev-gitmodules-untrusted", "dev-gitattributes-filter", "dev-gitconfig-exec"

_HEADER = re.compile(r'\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\\n]|\\.)*)")?\s*\]')
_KEY = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)\s*(=)?")
_ESCAPES = {"n": "\n", "t": "\t", "b": "\b", "\\": "\\", '"': '"'}

Entry = tuple[str, str, str, str, int]


def _value(lines: list[str], index: int, start: int) -> tuple[str, int]:
    """A value from `start` on line `index`, as git reads it: quotes, escapes, comments, `\\` continuations."""
    out, quoted, line, at = [], False, lines[index], start
    while True:
        if at >= len(line):
            if quoted:
                msg = f"line {index + 1}: a quoted value is not closed on its line"
                raise UnreadableError(msg)
            return "".join(out).strip(), index
        char = line[at]
        if char == "\\":
            if at + 1 == len(line):
                index += 1
                if index >= len(lines):
                    msg = "a continuation at the end of the file"
                    raise UnreadableError(msg)
                line, at = lines[index], 0
                continue
            if line[at + 1] not in _ESCAPES:
                msg = f"line {index + 1}: unknown escape \\{line[at + 1]}"
                raise UnreadableError(msg)
            out.append(_ESCAPES[line[at + 1]])
            at += 2
            continue
        if char == '"':
            quoted = not quoted
        elif char in "#;" and not quoted:
            return "".join(out).strip(), index
        else:
            out.append(char)
        at += 1


def entries(text: str) -> list[Entry]:
    """(section, subsection, key, value, line) for every variable; a key without `=` is `true`. Malformed refuses."""
    lines = text.replace("\r\n", "\n").split("\n")
    found: list[Entry] = []
    section, sub, index = "", "", 0
    while index < len(lines):
        line, at = lines[index], 0
        header = _HEADER.match(line)
        if header:
            section, sub, at = header.group(1).lower(), (header.group(2) or ""), header.end()
            if "." in section and not header.group(2):
                section, _, sub = section.partition(".")
        rest = line[at:].strip()
        if rest and rest[0] not in "#;":
            key = _KEY.match(line, at)
            if not key or not section:
                msg = f"line {index + 1}: not a git config line"
                raise UnreadableError(msg)
            value, last = _value(lines, index, key.end()) if key.group(2) else ("true", index)
            if not key.group(2) and line[key.end() :].strip()[:1] not in ("", "#", ";"):
                msg = f"line {index + 1}: not a git config line"
                raise UnreadableError(msg)
            found.append((section, sub, key.group(1).lower(), value, index + 1))
            index = last
        index += 1
    return found


def _lone_cr(c: Collector, rule: str) -> None:
    if re.search(r"\r(?!\n)", c.text):
        c.add(
            rule,
            "carriage-return",
            "a carriage return inside a line (the CVE-2025-48384 path trick)",
            line=c.line_of("\r"),
        )


_BAD_URL = re.compile(r"(?i)^(?:ext::|fd::|http://|git://|file:|-)|^[a-z0-9+.-]+::")


def gitmodules(c: Collector) -> None:
    _lone_cr(c, MODULES)
    paths: dict[str, str] = {}
    for section, sub, key, value, line in entries(c.text):
        if section != "submodule":
            continue
        if re.search(r"(?:^|[\\/])\.\.(?:[\\/]|$)|[\x00-\x1f]", sub):
            c.add(MODULES, f"name={norm(sub)}", "submodule name escapes its folder", line=line)
        if key == "url" and _BAD_URL.search(value.strip()):
            c.add(
                MODULES,
                f"{sub}.url={norm(value)}",
                f"submodule {sub} uses an untrusted URL scheme or an option",
                line=line,
            )
        elif key == "path":
            if re.search(r"(?:^|[\\/])\.\.(?:[\\/]|$)|^[-/\\]|^[a-zA-Z]:|[\x00-\x1f]", value):
                c.add(MODULES, f"{sub}.path={norm(value)}", f"submodule {sub} path escapes the work tree", line=line)
            other = paths.setdefault(value.lower(), value)
            if other != value:
                c.add(MODULES, f"path-case={norm(value.lower())}", "two submodule paths differ only in case", line=line)
        elif key == "update" and value.strip().startswith("!"):
            c.add(MODULES, f"{sub}.update={norm(value)}", f"submodule {sub} update runs a command", line=line)


_BUILTIN_DIFF = frozenset(
    [
        "ada",
        "bash",
        "bibtex",
        "cpp",
        "csharp",
        "css",
        "dts",
        "elixir",
        "fortran",
        "fountain",
        "golang",
        "html",
        "java",
        "kotlin",
        "markdown",
        "matlab",
        "objc",
        "pascal",
        "perl",
        "php",
        "python",
        "ruby",
        "rust",
        "scheme",
        "tex",
        "binary",
        "lfs",
    ]
)
_ALLOWED = {
    "filter": frozenset({"lfs"}),
    "diff": _BUILTIN_DIFF,
    "merge": frozenset({"ours", "binary", "text", "union", "lfs"}),
}
_ATTR = re.compile(r"(?<![\w!-])(filter|diff|merge)=(\S+)")


def gitattributes(c: Collector) -> None:
    for number, line in enumerate(c.lines, 1):
        if line.lstrip().startswith("#"):
            continue
        for kind, name in _ATTR.findall(line):
            if name not in _ALLOWED[kind]:
                c.add(
                    ATTRIBUTES, f"{kind}={name}", f"{kind} driver {name} runs a program git config names", line=number
                )


_EXEC_KEYS = re.compile(
    r"core\.(?:fsmonitor|sshcommand|pager|editor|hookspath|askpass|gitproxy|worktree)|diff\.external|sequence\.editor"
    r"|diff\..+\.(?:textconv|command)|filter\..+\.(?:clean|smudge|process)|merge\..+\.driver|credential(?:\..+)?\.helper"
    r"|gpg(?:\..+)?\.program|include(?:if\..+)?\.path|uploadpack\.packobjectshook|web\.browser|browser\..+\.(?:cmd|path)"
    r"|interactive\.difffilter|pager\..+|url\..+\.(?:insteadof|pushinsteadof)|http(?:\..+)?\.extraheader"
    r"|safe\.directory|ssh\.variant|man\..+\.(?:cmd|path)|mergetool\..+\.cmd|difftool\..+\.cmd|sendemail\..*"
)
_UNSAFE_VALUES = {
    "http.sslverify": "false",
    "transfer.fsckobjects": "false",
    "fetch.fsckobjects": "false",
    "protocol.allow": "always",
}


def gitconfig(c: Collector) -> None:
    _lone_cr(c, CONFIG)
    for section, sub, key, value, line in entries(c.text):
        name = ".".join(part for part in (section, sub.lower(), key) if part)
        plain = f"{section}.{key}"
        bool_fsmonitor = plain == "core.fsmonitor" and value.lower() in ("true", "false", "0", "1", "yes", "no")
        if (_EXEC_KEYS.fullmatch(name) and not bool_fsmonitor) or (
            section == "alias" and value.lstrip().startswith("!")
        ):
            c.add(CONFIG, f"{name}={norm(value)}", f"git config {name} runs a program or redirects git", line=line)
        elif _UNSAFE_VALUES.get(plain) == value.lower() or (
            section == "protocol" and key == "allow" and value.lower() == "always"
        ):
            c.add(CONFIG, f"{name}={norm(value)}", f"git config {name}={value} drops a safety check", line=line)
