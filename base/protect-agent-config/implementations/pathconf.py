"""`git config` as a writer: keys that run code, `--file` at a protected file, the environment routes (stdlib only)."""

from __future__ import annotations

import re
import shlex
from typing import Any

from chock_shellparse import abbreviates
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
_READS = frozenset(("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool", "--list"))
_EDITS = frozenset(("--add", "--replace-all", "--unset", "--unset-all"))
_SECTION_EDITS = frozenset(("--remove-section", "--rename-section"))
# Every long option of `git config`, with whether it takes a value: git accepts any unambiguous prefix of one.
_LONG = {
    **dict.fromkeys((*_READS, *_EDITS, *_SECTION_EDITS), False),
    **dict.fromkeys(("--global", "--system", "--local", "--worktree", "--edit", "--fixed-value", "--null"), False),
    **dict.fromkeys(("--name-only", "--includes", "--no-includes", "--show-origin", "--show-scope", "--bool"), False),
    **dict.fromkeys(("--int", "--bool-or-int", "--path", "--expiry-date", "--no-type", "--all", "--help"), False),
    **dict.fromkeys(("--file", "--blob", "--type", "--default", "--comment", "--value"), True),
}
_SUBCOMMANDS = frozenset(("set", "unset", "get", "list", "edit", "rename-section", "remove-section"))
_SHORT_VALUE = "ft"  # `-f FILE` and `-t TYPE` take the rest of the word, or the next word
# Git commands an alias can name and still run no program of the agent's choosing; `submodule` (foreach), `bisect` (run),
# `filter-branch`, `difftool`, `mergetool`, `grep -O`, `help` and a name that is not here are left out.
_GIT_COMMANDS = frozenset(
    (
        *("add", "am", "annotate", "apply", "archive", "blame", "branch", "bundle", "cat-file", "checkout", "cherry"),
        *("cherry-pick", "clean", "clone", "commit", "config", "count-objects", "describe", "diff", "fetch"),
        *("format-patch", "fsck", "gc", "hash-object", "init", "log", "ls-files", "ls-remote", "ls-tree"),
        *("merge", "merge-base", "mv", "name-rev", "notes", "pull", "push", "range-diff", "rebase", "reflog"),
        *("remote", "repack", "replace", "reset", "restore", "rev-list", "rev-parse", "revert", "rm", "shortlog"),
        *("show", "show-branch", "sparse-checkout", "stash", "status", "switch", "symbolic-ref", "tag", "worktree"),
        *("update-index", "update-ref", "whatchanged", "diff-tree", "diff-files", "diff-index", "prune"),
    )
)
_KEY_ENV = re.compile(r"GIT_CONFIG_KEY_\d+")
_LETTERS = re.compile(r"[A-Za-z]{1,3}")


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


def _long(name: str) -> list[str]:
    """The long options a word can stand for: itself when it is one, else every option it abbreviates."""
    return [name] if name in _LONG else [full for full in _LONG if abbreviates(name, full, 3)]


def _options(args: list[str]) -> tuple[set[str], list[str], list[str]]:
    """The long options (abbreviations and bundled short letters read out), the words and the `--file` values."""
    flags: set[str] = set()
    words, files, at, done = [], [], 0, False
    while at < len(args):
        arg, at = args[at], at + 1
        if done or not arg.startswith("-") or arg == "-":
            words.append(arg)
        elif arg == "--":
            done = True
        elif arg.startswith("--"):
            name, equals, value = arg.partition("=")
            found = _long(name)
            flags.update(found)
            if any(_LONG[f] for f in found):
                value, at = (value, at) if equals or at >= len(args) else (args[at], at + 1)
                files += [value] if "--file" in found and (equals or value) else []
        else:
            at += _bundle(arg, args[at] if at < len(args) else "", flags, files)
    return flags, words, files


def _bundle(arg: str, following: str, flags: set[str], files: list[str]) -> int:
    """Short letters of one word (`-ef`, `-l`, `-fFILE`); how many following words they took."""
    for k, char in enumerate(arg[1:], 1):
        tail = arg[k + 1 :]
        if char in _SHORT_VALUE:
            value = tail or following
            files += [value] if char == "f" and value else []
            if _LETTERS.fullmatch(tail) and "e" in tail:  # `-fe`: git reads a file `e`; the guard reads an edit too
                flags.add("--edit")
            return 0 if tail else int(bool(following))
        flags.update({"e": {"--edit"}, "l": {"--list"}}.get(char, ()))
    return 0


def harmless_alias(key: str, value: str) -> bool:
    """Whether an alias value runs no program: it starts with a git command that takes no program (a name that is not one
    would run `git-NAME` from the PATH), and a `!` shell alias, a leading option (`-c`) or an `--exec` option is none of that."""
    words = value.split()
    return (
        key.lower().startswith("alias.")
        and not DYNAMIC.search(value)
        and words[:1] != []
        and words[0] in _GIT_COMMANDS
        and not any(w == "-x" or w.startswith("--exec") for w in words)
    )


def config(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """`git config` that writes: a code-running key, a section holding one, `--edit`, or `--file` at a protected file."""
    flags, words, files = _options(args)
    sub = words.pop(0) if words and words[0] in _SUBCOMMANDS else ""  # git 2.46: `git config set KEY VALUE`
    if "--edit" in flags or sub == "edit":
        return True  # the editor is whatever GIT_EDITOR or core.editor names
    if flags & _READS or sub in ("get", "list"):
        return False
    sections = sub in ("rename-section", "remove-section") or bool(flags & _SECTION_EDITS)
    unsetting = sub == "unset" or bool(flags & {"--unset", "--unset-all"})
    if not (sections or unsetting or sub == "set" or flags & _EDITS or len(words) > 1):
        return False  # `git config KEY` only reads
    if any(w.reaches(f, env) for f in files):
        return True
    if sections:
        return any(name.split(".")[0].lower() in _SECTIONS or DYNAMIC.search(name) for name in words)
    key, value = (*words, "", "")[:2]
    return code_key(key) and (unsetting or not harmless_alias(key, value))
