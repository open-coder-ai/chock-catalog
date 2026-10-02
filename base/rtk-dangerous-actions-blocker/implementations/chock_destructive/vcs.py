"""git rows: history rewrites, remote deletions and worktree discards (shared byte for byte)."""

from chock_shellparse import Cmd, abbreviates, flags_of, git_parts, operands

Hit = tuple[str, str] | None
_LEASE = "--force-with-lease"


def _whole_tree(targets: list[str]) -> str:
    """The pathspec that names the whole worktree ('.', './', ':/', '*'), or ''."""
    return next((t for t in targets if t.rstrip("/") == "." or t in (":/", "*")), "")


def push(rest: list[str]) -> Hit:
    flags, targets = flags_of(rest), operands(rest)
    forced = min((t for t in targets if t.startswith("+") or ":+" in t), default="")
    deleted = min((t for t in targets if t.startswith(":") and len(t) > 1), default="")
    if flags & {"-f", "--force"}:
        return "push-force", ""
    if forced:
        return "push-force-refspec", forced
    if any(abbreviates(f, "--mirror", 4) for f in flags):
        return "push-mirror", ""
    if flags & {"-d"} or any(abbreviates(f, "--delete", 5) or abbreviates(f, "--prune", 5) for f in flags) or deleted:
        return "push-delete", deleted or "--delete/--prune"
    # A lease abbreviation longer than --force (git takes unambiguous prefixes) with no '=<ref>' value trusts the last fetch.
    bare = any(len(a) > len("--force") and _LEASE.startswith(a) for a in rest)
    return ("push-lease-bare", "") if bare else None


def worktree(sub: str, rest: list[str]) -> Hit:
    flags, target = flags_of(rest), _whole_tree(operands(rest))
    if sub == "checkout" and target:
        return "checkout-all", target
    staged_only = bool(flags & {"-S", "--staged"}) and not flags & {"-W", "--worktree"}
    return ("restore-all", target) if sub == "restore" and target and not staged_only else None


def history(sub: str, rest: list[str]) -> Hit:
    first = operands(rest)[:1]
    if sub in ("filter-branch", "filter-repo"):
        return "history-rewrite", sub
    if sub == "reflog" and first in (["expire"], ["delete"]):
        return "history-rewrite", f"reflog {first[0]}"
    if sub == "gc" and any(a in ("--prune=now", "--prune=all") for a in rest):
        return "history-rewrite", "gc --prune=now"
    return ("history-rewrite", "update-ref -d") if sub == "update-ref" and "-d" in flags_of(rest) else None


def local(sub: str, rest: list[str]) -> Hit:
    """reset --hard, clean -f, stash drop/clear, branch -D."""
    flags = flags_of(rest)
    first = operands(rest)[:1]
    found = {
        "reset": ("reset-hard", "") if any(abbreviates(f, "--hard", 3) for f in flags) else None,
        "clean": ("clean-force", "") if any(f == "-f" or abbreviates(f, "--force", 3) for f in flags) else None,
        "stash": ("stash-drop", first[0]) if first in (["drop"], ["clear"]) else None,
        "branch": (
            ("branch-force-delete", "")
            if "-D" in flags or (flags & {"-d", "--delete"} and flags & {"-f", "--force"})
            else None
        ),
    }
    return found.get(sub)


def git(cmd: Cmd) -> Hit:
    sub, _, rest = git_parts(cmd.args)
    if sub == "push":
        return push(rest)
    return worktree(sub, rest) or history(sub, rest) or local(sub, rest)
