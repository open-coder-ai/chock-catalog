"""The ref names a git command would create, read the way git's option parser reads them (stdlib only)."""

from __future__ import annotations

from typing import NamedTuple


class Spec(NamedTuple):
    """One subcommand: long options (for prefix abbreviation), which take a value, and which mean "creates nothing"."""

    longs: frozenset[str]
    short_values: str
    long_values: frozenset[str]
    skip: frozenset[str]


def _set(words: str) -> frozenset[str]:
    return frozenset(words.split())


_LIST = "--list --contains --no-contains --merged --no-merged --points-at --sort --format --column"
BRANCH = Spec(
    _set(
        f"{_LIST} --delete --all --remotes --verbose --show-current --set-upstream-to --unset-upstream --move --copy"
        " --edit-description --force --track --no-track --create-reflog --recurse-submodules --quiet --ignore-case"
        " --omit-empty --abbrev --no-abbrev --color --no-color"
    ),
    "u",
    _set("--set-upstream-to --sort --format --points-at"),
    _set(f"{_LIST} -d -D -l -a -r -v -u --delete --all --remotes --verbose --show-current --set-upstream-to")
    | _set("--unset-upstream --edit-description"),
)
TAG = Spec(
    _set(
        f"{_LIST} --delete --verify --message --file --local-user --cleanup --annotate --sign --no-sign --force"
        " --create-reflog --edit --trailer --ignore-case --omit-empty --color"
    ),
    "mFu",
    _set("--message --file --local-user --cleanup --trailer --sort --format --points-at"),
    _set(f"{_LIST} -d -l -v -n --delete --verify"),
)
CHECKOUT = Spec(
    _set(
        "--orphan --track --no-track --detach --force --merge --conflict --ours --theirs --patch --quiet --progress"
        " --recurse-submodules --overlay --no-overlay --pathspec-from-file --ignore-other-worktrees --guess"
    ),
    "bB",
    _set("--orphan --conflict --pathspec-from-file"),
    frozenset(),
)
SWITCH = Spec(
    _set(
        "--create --force-create --orphan --conflict --detach --guess --no-guess --force --discard-changes --merge"
        " --quiet --progress --track --no-track --recurse-submodules --ignore-other-worktrees"
    ),
    "cC",
    _set("--create --force-create --orphan --conflict"),
    frozenset(),
)
WORKTREE = Spec(
    _set("--force --detach --checkout --no-checkout --lock --reason --orphan --quiet --track --no-track --guess-remote"),
    "bB",
    _set("--reason"),
    frozenset(),
)
PUSH = Spec(
    _set(
        "--all --mirror --tags --follow-tags --delete --dry-run --porcelain --force --force-with-lease --repo"
        " --push-option --receive-pack --exec --set-upstream --signed --atomic --prune --verbose --quiet --verify"
    ),
    "o",
    _set("--repo --push-option --receive-pack --exec"),
    _set("-d --delete"),
)
FETCH = Spec(
    _set(
        "--all --append --atomic --depth --deepen --shallow-since --shallow-exclude --unshallow --dry-run --force"
        " --keep --multiple --prune --prune-tags --no-tags --tags --refmap --recurse-submodules --jobs --upload-pack"
        " --quiet --verbose --server-option --negotiation-tip --filter --update-head-ok"
    ),
    "oj",
    _set(
        "--depth --deepen --shallow-since --shallow-exclude --refmap --jobs --upload-pack --server-option"
        " --negotiation-tip --filter"
    ),
    frozenset(),
)
UPDATE_REF = Spec(_set("--no-deref --create-reflog --stdin"), "m", frozenset(), _set("-d"))


def _long(name: str, spec: Spec) -> str:
    """git accepts any unambiguous prefix of a long option; map one to the option it names."""
    if name in spec.longs:
        return name
    matches = [full for full in spec.longs if full.startswith(name)]
    return matches[0] if len(matches) == 1 else name


def parse(args: list[str], spec: Spec) -> tuple[set[str], list[str], list[tuple[str, str]]]:
    """(flags seen, operands, (option, value) pairs); a short cluster stops at its first value-taking letter."""
    flags: set[str] = set()
    operands: list[str] = []
    values: list[tuple[str, str]] = []
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            operands += args[i:]
            break
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            name = _long(name, spec)
            flags.add(name)
            if name in spec.long_values:
                if not eq and i < len(args):
                    value, i = args[i], i + 1
                values.append((name, value))
        elif arg.startswith("-") and len(arg) > 1:
            for at, char in enumerate(arg[1:], 2):
                flags.add(f"-{char}")
                if char in spec.short_values:
                    value = arg[at:]
                    if not value and i < len(args):
                        value, i = args[i], i + 1
                    values.append((f"-{char}", value))
                    break
        else:
            operands.append(arg)
    return flags, operands, values


def _refspec_destination(refspec: str, *, needs_colon: bool) -> str:
    """The ref a push or fetch refspec writes; '' for a deletion (`:dst`) or, for fetch, no destination."""
    src, colon, dst = refspec.lstrip("+").partition(":")
    if not colon:
        return "" if needs_colon else src
    return dst if src else ""


def created_refs(sub: str, rest: list[str], doc: str) -> list[str]:
    """Every ref name `git <sub> <rest...>` would create or point somewhere new."""
    if sub in ("branch", "tag"):
        flags, operands, _ = parse(rest, BRANCH if sub == "branch" else TAG)
        if flags & (BRANCH if sub == "branch" else TAG).skip:
            return []
        renames = sub == "branch" and flags & {"-m", "-M", "-c", "-C", "--move", "--copy"}
        return operands[-1:] if renames else operands[:1]
    if sub in ("checkout", "switch"):
        spec = CHECKOUT if sub == "checkout" else SWITCH
        creators = {"-b", "-B", "-c", "-C", "--orphan", "--create", "--force-create"}
        return [value for name, value in parse(rest, spec)[2] if name in creators]
    if sub == "worktree" and rest[:1] == ["add"]:
        return [value for name, value in parse(rest[1:], WORKTREE)[2] if name in ("-b", "-B")]
    if sub in ("push", "fetch"):
        spec = PUSH if sub == "push" else FETCH
        flags, operands, _ = parse(rest, spec)
        if flags & spec.skip:
            return []
        found = (_refspec_destination(ref, needs_colon=sub == "fetch") for ref in operands[1:])
        return [ref for ref in found if ref]
    if sub == "update-ref":
        flags, operands, _ = parse(rest, UPDATE_REF)
        if "--stdin" in flags:
            lines = (line.split() for line in doc.splitlines())
            return [words[1] for words in lines if len(words) > 1 and words[0] in ("create", "update")]
        return [] if flags & UPDATE_REF.skip else operands[:1]
    return []
