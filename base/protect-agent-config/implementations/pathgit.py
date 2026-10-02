"""`git` as a writer: checkout, restore, rm, mv, clean and the hook path (stdlib only)."""

from __future__ import annotations

from typing import Any

from chock_shellparse import abbreviates, flags_of, git_parts
from pathconf import code_key, config
from pathmatch import DYNAMIC, values

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


def git(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """checkout, restore, rm, mv overwrite or delete worktree files; `restore` and `rm` always take paths."""
    if any("core.hookspath" in a.lower() for a in args) and not {"--get", "--list", "-l"} & set(args):
        return True
    sub, conf, rest = git_parts(args)
    alias = bool(sub) and sub not in _BUILTIN and w.hit(w.text)  # an alias the line does not define may run anything
    fused = [a[2:] for a in args[: len(args) - len(rest)] if a.startswith("-c") and "=" in a]  # `-ckey=value`
    if alias or any(code_key(c.split("=", 1)[0]) for c in (*conf, *fused)):
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
