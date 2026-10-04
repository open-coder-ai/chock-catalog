"""`git config` as a writer: keys that run code, `--file` at a protected file, the environment routes (stdlib only)."""
# Measurement-only change: timing a one-policy PR (run 2).

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
# Git commands an alias can name and still run no program of the agent's choosing, as long as no option below is given. Left out:
# `submodule` (foreach), `bisect` (run), `filter-branch`, `difftool`, `mergetool`, `grep -O`, `help` and a name that is not here
# (it would run `git-NAME` from the PATH). `config` is judged as a `git config` of its own (`_benign`).
_GIT_COMMANDS = frozenset(
    (
        *("add", "am", "annotate", "apply", "archive", "blame", "branch", "bundle", "cat-file", "checkout", "cherry"),
        *("cherry-pick", "clean", "clone", "commit", "config", "count-objects", "describe", "diff", "fetch"),
        *("format-patch", "fsck", "gc", "hash-object", "init", "log", "ls-files", "ls-remote", "ls-tree"),
        *("merge", "merge-base", "mv", "name-rev", "notes", "pull", "push", "range-diff", "rebase", "reflog"),
        *("remote", "repack", "replace", "reset", "restore", "rev-list", "rev-parse", "revert", "rm", "shortlog"),
        *("show", "show-branch", "sparse-checkout", "stash", "status", "switch", "symbolic-ref", "tag", "worktree"),
        *("for-each-ref", "show-ref"),
        *("update-index", "update-ref", "whatchanged", "diff-tree", "diff-files", "diff-index", "prune"),
    )
)
# Options that make a command in an alias run a program: `--exec`, `--upload-pack`, `--receive-pack`, `--template`, `--config`,
# `-x` of a rebase, `-u` (upload-pack) and `-c` of a clone, a merge strategy that is not one git ships (`git-merge-NAME`).
# A long option is read by every prefix of its name, since git accepts the unambiguous ones (`--u=`, `--te=`, `--co=`).
_EXECS = ("--exec", "--upload-pack", "--receive-pack")
_LONG_RISKY = {
    **dict.fromkeys(("archive", "ls-remote", "push", "fetch", "pull"), _EXECS),
    "rebase": ("--exec",),
    "clone": ("--exec", "--upload-pack", "--config", "--template"),
    "init": ("--template",),
}
_SHORT_RISKY = {
    "fetch": re.compile(r"-[A-Za-z]*u"),
    "pull": re.compile(r"-[A-Za-z]*[ux]"),
    "rebase": re.compile(r"-[A-Za-z]*x"),
    "clone": re.compile(r"-[A-Za-z]*[uc]"),
}
_ANY_EXEC = re.compile(r"--exe")  # no git option but `--exec` starts so
_FORMAT = re.compile(r"""--(?:format|pretty)=(?:t?format:)?(?:'[^']*'|"[^"]*"|\S+)""")
_QUOTES = str.maketrans("", "", "'\"\\")
_STRATEGIES = frozenset(("ours", "recursive", "resolve", "octopus", "subtree", "ort"))
_STRATEGY_COMMANDS = frozenset(("merge", "rebase", "pull", "cherry-pick", "revert"))
_STRATEGY_OPTION = re.compile(r"(?:--str[a-z-]*=?|-s)(.*)")
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


def _strategy(words: list[str]) -> bool:
    """Whether a word asks for a merge strategy other than the ones git ships (it would run `git-merge-NAME` from the PATH)."""
    for at, word in enumerate(words):
        found = _STRATEGY_OPTION.fullmatch(word)
        if found and (found[1] or words[at + 1 : at + 2] or [""])[0] not in _STRATEGIES:
            return True
    return False


def _runs_program(command: str, word: str) -> bool:
    """Whether an option word of an alias body makes `git COMMAND` run a program."""
    name = word.split("=", 1)[0]
    short = _SHORT_RISKY.get(command)
    return bool(
        _ANY_EXEC.match(word)
        or any(abbreviates(name, full, 3) for full in _LONG_RISKY.get(command, ()))
        or (short and short.match(word))
    )


def _plain(value: str) -> str:
    """An alias value as git reads its words: the text of a `--format` or `--pretty` option is only printed (a `[`, a `*`, a
    `%` in it runs and matches nothing), and quotes and backslashes only group words."""
    return _FORMAT.sub("--format=", value).translate(_QUOTES)


def harmless_alias(key: str, value: str) -> bool:
    """Whether an alias value runs no program: it starts with a git command that takes no program (a name that is not one
    would run `git-NAME` from the PATH), and a `!` shell alias, a leading option (`-c`) or an option that runs one is none of that."""
    plain = _plain(value)
    words = plain.split()
    return (
        key.lower().startswith("alias.")
        and not DYNAMIC.search(plain)
        and words[:1] != []
        and words[0] in _GIT_COMMANDS
        and not any(_runs_program(words[0], w) for w in words[1:])
        and not (words[0] in _STRATEGY_COMMANDS and _strategy(words[1:]))
    )


def _benign(w: Any, key: str, value: str, env: dict[str, str]) -> bool:
    """An alias value that runs no program, names no protected path, and is no `git` command this guard refuses (the alias
    runs later, where nothing judges it: `config core.hooksPath h`, `clean -fdx`, `checkout -- .claude`)."""
    return harmless_alias(key, value) and not _names(w, value, env) and not w.git_refuses(value.split(), env)


def _names(w: Any, value: str, env: dict[str, str]) -> bool:
    """Whether an alias value names a protected path, or a folder holding one (`--output=` or `-o` at a config folder)."""
    words = [t for t in re.split(r"[\s=]+", value) if t and not t.startswith("-")]
    return w.hit(value) or any(w.reaches(t, env, parents=True, whole=True) for t in words)


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
    return code_key(key) and (unsetting or not _benign(w, key, value, env))
