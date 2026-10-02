"""`git config` as a writer: keys that run code, `--file` at a protected file, the environment routes (stdlib only)."""

from __future__ import annotations

import re
import shlex
from typing import Any

from pathmatch import DYNAMIC

# Keys that make git run a program (a pager, a hook path, an alias, a filter ...): set in .git/config they run for the next person.
_CODE = re.compile(
    r"(?:core\.(?:hookspath|fsmonitor|pager|editor|sshcommand|askpass|gitproxy|alternaterefscommand)"
    r"|sequence\.editor|diff\.external|diff\..+\.(?:textconv|command)|merge\..+\.driver"
    r"|filter\..+\.(?:clean|smudge|process)|credential\.helper|credential\..+\.helper|alias\..+"
    r"|include\.path|includeif\..+\.path|gpg\.program|gpg\..+\.program|uploadpack\.packobjectshook"
    r"|receive\.procreceiverefs|pager\..+|web\.browser|browser\..+\.cmd|man\..+\.cmd|sendemail\..+"
    r"|remote\..+\.(?:uploadpack|receivepack|vcs)|(?:difftool|mergetool)\..+\.(?:cmd|path)|trailer\..+\.cmd"
    r"|submodule\..+\.update)"
)
# Sections that hold such keys: removing or renaming one rewrites them.
_SECTIONS = frozenset(
    (
        *("core", "alias", "credential", "diff", "merge", "filter", "include", "includeif", "gpg", "pager", "web"),
        *("browser", "man", "sendemail", "uploadpack", "receive", "sequence", "remote", "difftool", "mergetool"),
        *("trailer", "submodule"),
    )
)
_READS = frozenset(("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool"))
_READS |= frozenset(("--list", "-l"))
_EDITS = frozenset(("--add", "--replace-all", "--unset", "--unset-all", "-e", "--edit"))
_SECTION_EDITS = frozenset(("--remove-section", "--rename-section"))
_VALUED = frozenset(("--blob", "--type", "--default", "--comment"))
_FILE = re.compile(r"--file=(.*)|-f(.+)")
_KEY_ENV = re.compile(r"GIT_CONFIG_KEY_\d+")


def code_key(key: str) -> bool:
    """Whether a config key runs a program; a key the line does not spell out may be one."""
    return DYNAMIC.search(key) is not None or _CODE.fullmatch(key.lower()) is not None


def route(env: dict[str, str]) -> bool:
    """Whether the environment of a command sets a code-running config key (GIT_CONFIG_KEY_n, GIT_CONFIG_PARAMETERS)."""
    keys = [v for k, v in env.items() if _KEY_ENV.fullmatch(k)]
    try:
        entries = shlex.split(env.get("GIT_CONFIG_PARAMETERS", ""))
    except ValueError:
        return True  # keys the guard cannot read may be any
    return any(code_key(k) for k in [*keys, *(e.split("=", 1)[0] for e in entries)])


def config(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """`git config` that writes: a code-running key, a section holding one, or `--file` at a protected file."""
    flags, words, files, skip = set(), [], [], False
    for at, arg in enumerate(args):
        found = _FILE.fullmatch(arg)
        if skip:
            skip = False
        elif arg in ("-f", "--file", *_VALUED):
            skip = True
            files += [args[at + 1]] if arg in ("-f", "--file") and at + 1 < len(args) else []
        elif found:
            files.append(found[1] or found[2])
        elif arg.startswith("-") and len(arg) > 1:
            flags.add(arg)
        else:
            words.append(arg)
    if flags & _READS or not (flags & (_EDITS | _SECTION_EDITS) or len(words) > 1):
        return False  # `git config KEY` and `--get`, `--list` only read
    if flags & _SECTION_EDITS:
        return any(name.split(".")[0].lower() in _SECTIONS or DYNAMIC.search(name) for name in words)
    return bool(flags & {"-e", "--edit"}) or any(w.reaches(f, env) for f in files) or any(map(code_key, words[:1]))
