"""`git` as a writer: checkout, restore, rm, mv, clean, the hook path, output options and the programs it runs (stdlib only)."""

from __future__ import annotations

import shlex
from typing import Any

from chock_shellparse import abbreviates, flags_of, git_parts
from pathconf import code_key, config
from pathmatch import DYNAMIC, expand, values

# Every git command (porcelain and plumbing, as `git help -a` lists them); any other word is a user alias, or `git-NAME` from the PATH.
_BUILTIN = frozenset(
    (
        *("add", "am", "annotate", "apply", "archive", "bisect", "blame", "branch", "bundle", "cat-file", "check-attr"),
        *("check-ignore", "check-ref-format", "checkout", "checkout-index", "cherry", "cherry-pick", "clean", "clone"),
        *(
            "column",
            "commit",
            "commit-graph",
            "commit-tree",
            "config",
            "count-objects",
            "credential",
            "describe",
            "diff",
        ),
        *("diff-files", "diff-index", "diff-tree", "difftool", "fast-export", "fast-import", "fetch", "filter-branch"),
        *("fmt-merge-msg", "for-each-ref", "for-each-repo", "format-patch", "fsck", "gc", "get-tar-commit-id", "grep"),
        *("hash-object", "help", "hook", "index-pack", "init", "interpret-trailers", "log", "ls-files", "ls-remote"),
        *("ls-tree", "mailinfo", "mailsplit", "maintenance", "merge", "merge-base", "merge-file", "merge-index"),
        *("merge-tree", "mergetool", "mktag", "mktree", "multi-pack-index", "mv", "name-rev", "notes", "pack-objects"),
        *("pack-refs", "patch-id", "prune", "prune-packed", "pull", "push", "range-diff", "read-tree", "rebase"),
        *("reflog", "remote", "repack", "replace", "rerere", "reset", "restore", "rev-list", "rev-parse", "revert"),
        *("rm", "send-email", "shortlog", "show", "show-branch", "show-index", "show-ref", "sparse-checkout", "stash"),
        *("status", "stripspace", "submodule", "switch", "symbolic-ref", "tag", "unpack-file", "unpack-objects"),
        *("update-index", "update-ref", "update-server-info", "var", "verify-commit", "verify-pack", "verify-tag"),
        *("version", "whatchanged", "worktree", "write-tree", "gui", "citool", "instaweb", "daemon", "web--browse"),
        *("upload-pack", "receive-pack", "upload-archive", "remote-ext", "request-pull", "scalar", "cvsimport", "svn"),
    )
)


# Variables whose value git (or ssh) runs as a shell command.
_PROGRAM_ENV = frozenset(
    (
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_PAGER",
        "GIT_SSH_COMMAND",
        "GIT_SSH",
        "GIT_ASKPASS",
        "GIT_EXTERNAL_DIFF",
    ),
) | frozenset(("GIT_PROXY_COMMAND", "EDITOR", "VISUAL", "PAGER", "SSH_ASKPASS"))
_FILTERS = ("--env-filter", "--tree-filter", "--index-filter", "--parent-filter", "--msg-filter", "--commit-filter")
_DIFFERS = frozenset(("log", "diff", "show", "whatchanged", "diff-tree", "diff-index", "diff-files"))
_FLOOR = 3  # `--` and one letter


def git(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """checkout, restore, rm, mv overwrite or delete worktree files; `restore` and `rm` always take paths."""
    if any("core.hookspath" in a.lower() for a in args) and not {"--get", "--list", "-l"} & set(args):
        return True
    sub, conf, rest = git_parts(args)
    alias = (
        bool(sub) and sub not in _BUILTIN and _reaches_any(w, args, env)
    )  # an alias the line does not define may run anything
    fused = [a[2:] for a in args[: len(args) - len(rest)] if a.startswith("-c") and "=" in a]  # `-ckey=value`
    if (
        alias
        or any(code_key(c.split("=", 1)[0]) for c in (*conf, *fused))
        or any(w.sub(text) for text in _programs(sub, rest, env))
        or _writes_output(w, sub, rest, env)
    ):
        return True
    if sub == "config":
        return config(w, rest, env)
    if sub == "clean":
        return clean(w, rest, env)
    if sub not in ("checkout", "restore", "rm", "mv") or (sub == "restore" and _index_only(rest)):
        return False
    paths = rest[rest.index("--") + 1 :] if "--" in rest else []
    static = [t for t in values(rest) if sub != "checkout" or t in paths or not DYNAMIC.search(t)]
    return any(w.reaches(t, env, parents=True, whole=sub in ("rm", "mv")) for t in static)


def _values(args: list[str], short: str, longs: tuple[str, ...]) -> list[str]:
    """The values given to a short option (`-x CMD`, `-xCMD`, `-ix CMD`) and to long options by any prefix (`--exec=CMD`, `--exec CMD`)."""
    found, at = [], 0
    while at < len(args):
        arg, at = args[at], at + 1
        name, equals, value = arg.partition("=")
        if arg.startswith("--"):
            if any(abbreviates(name, full, _FLOOR) for full in longs):
                found.append(value if equals else (args[at : at + 1] or [""])[0])
                at += not equals
        elif short and arg.startswith("-") and short in arg[1:]:
            tail = arg[1:].partition(short)[2]
            found.append(tail or (args[at : at + 1] or [""])[0])
            at += not tail
    return found


def _programs(sub: str, args: list[str], env: dict[str, str]) -> list[str]:
    """The shell text git runs for this command: an editor or pager variable, `rebase -x`, `bisect run`, a `filter-branch` filter,
    `submodule foreach`, `difftool -x` (text with a variable in it is left alone)."""
    found = [v for k, v in env.items() if k in _PROGRAM_ENV]
    if sub == "rebase":
        found += _values(args, "x", ("--exec",))
    elif sub == "difftool":
        found += _values(args, "x", ("--extcmd",))
    elif sub == "filter-branch":
        found += _values(args, "", _FILTERS)
    elif sub == "bisect" and args[:1] == ["run"]:
        found.append(shlex.join(args[1:]))
    elif sub == "submodule" and "foreach" in args:
        found.append(" ".join(a for a in args[args.index("foreach") + 1 :] if not a.startswith("-")))
    return [text for text in found if "$" not in text]


def _writes_output(w: Any, sub: str, args: list[str], env: dict[str, str]) -> bool:
    """`log --output=FILE` and its kin write FILE; `format-patch -o DIR` writes patch files into DIR."""
    files = _values(args, "", ("--output",)) if sub in _DIFFERS else []
    folders = _values(args, "o", ("--output-directory",)) if sub == "format-patch" else []
    return any(w.reaches(t, env) for t in files) or any(w.reaches(t, env, parents=True) for t in folders)


def _reaches_any(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """Whether an argument, a glob or a path from the working directory, is a protected path (a variable the line does not set is not)."""
    known = [t for t in (expand(a, env) for a in values(args)) if "$" not in t]
    return any(w.reaches(t, env, parents=False) for t in known)


def _index_only(args: list[str]) -> bool:
    """`restore --staged` changes the index alone, unless `--worktree` (any unambiguous prefix, or -W) asks for the files too."""
    return "--staged" in args and not any(f == "-W" or abbreviates(f, "--worktree", 3) for f in flags_of(args))


def clean(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """`git clean` removes untracked files: each pathspec is a removal target; -x or -X reaches ignored files tree-wide."""
    letters, specs, skip = set(), [], False
    for at, arg in enumerate(args):
        if skip:
            skip = False
        elif arg == "--":
            specs += args[at + 1 :]
            break
        elif arg.startswith("--"):
            letters.add(arg.split("=", 1)[0])
            skip = arg == "--exclude"
        elif arg.startswith("-") and len(arg) > 1:
            for k, char in enumerate(arg[1:]):
                letters.add(f"-{char}")
                if char == "e":  # the rest of the word, or the next word, is a pattern
                    skip = k == len(arg) - 2
                    break
        else:
            specs.append(arg)
    if letters & {"-n", "--dry-run"}:
        return False
    ignored = bool(letters & {"-x", "-X"})
    # a pathspec that is the repository folder (`.`, `./`) or one above it holds every protected path, as -x does
    return any(w.reaches(t, env, parents=True, whole=True) for t in specs) or (ignored and not specs)
