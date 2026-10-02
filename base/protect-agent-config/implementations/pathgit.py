"""`git` as a writer: checkout, restore, rm, mv, clean and the hook path (stdlib only)."""

from __future__ import annotations

from typing import Any

from chock_shellparse import git_parts
from pathconf import code_key, config
from pathmatch import DYNAMIC, values


def git(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """checkout, restore, rm, mv overwrite or delete worktree files; `restore` and `rm` always take paths."""
    if any("core.hookspath" in a.lower() for a in args) and not {"--get", "--list", "-l"} & set(args):
        return True
    sub, conf, rest = git_parts(args)
    fused = [a[2:] for a in args[: len(args) - len(rest)] if a.startswith("-c") and "=" in a]  # `-ckey=value`
    if any(code_key(c.split("=", 1)[0]) for c in (*conf, *fused)):
        return True
    if sub == "config":
        return config(w, rest, env)
    if sub == "clean":
        return clean(w, rest, env)
    if sub not in ("checkout", "restore", "rm", "mv") or ("--staged" in rest and sub == "restore"):
        return False
    paths = rest[rest.index("--") + 1 :] if "--" in rest else []
    static = [t for t in values(rest) if sub != "checkout" or t in paths or not DYNAMIC.search(t)]
    return any(w.reaches(t, env, parents=True, whole=sub in ("rm", "mv")) for t in static)


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
    return any(w.reaches(t, env, parents=True, whole=ignored) for t in specs) or (ignored and not specs)
