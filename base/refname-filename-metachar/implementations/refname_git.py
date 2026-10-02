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
# The filters that put branch and tag into list mode; --sort, --format, --column and -v do not, and a name after
# them is still created (git 2.43, checked).
_FILTERS = "--contains --no-contains --merged --no-merged --points-at"
BRANCH = Spec(
    _set(
        f"{_LIST} --delete --all --remotes --verbose --show-current --set-upstream-to --unset-upstream --move --copy"
        " --edit-description --force --track --no-track --create-reflog --recurse-submodules --quiet --ignore-case"
        " --omit-empty --abbrev --no-abbrev --color --no-color"
    ),
    "u",
    _set("--set-upstream-to --sort --format --points-at"),
    _set(f"{_FILTERS} -d -D -l -a -r -u --delete --list --all --remotes --show-current --set-upstream-to")
    | _set("--unset-upstream --edit-description"),
)
TAG = Spec(
    _set(
        f"{_LIST} --delete --verify --message --file --local-user --cleanup --annotate --sign --no-sign --force"
        " --create-reflog --edit --trailer --ignore-case --omit-empty --color"
    ),
    "mFu",
    _set("--message --file --local-user --cleanup --trailer --sort --format --points-at"),
    _set(f"{_FILTERS} -d -l -v -n --delete --list --verify"),
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
    _set(
        "--force --detach --checkout --no-checkout --lock --reason --orphan --quiet --track --no-track --guess-remote"
    ),
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
SYMBOLIC_REF = Spec(_set("--delete --quiet --short --no-recurse --recurse"), "m", frozenset(), _set("-d --delete"))


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


def _branch_or_tag(sub: str, rest: list[str], _doc: str) -> list[str]:
    spec = BRANCH if sub == "branch" else TAG
    flags, operands, _ = parse(rest, spec)
    if flags & spec.skip:
        return []
    renames = sub == "branch" and flags & {"-m", "-M", "-c", "-C", "--move", "--copy"}
    return operands[-1:] if renames else operands[:1]


def _tracked_name(remote_ref: str) -> str:
    """The local branch `--track origin/x` creates: the remote-tracking name without its remote."""
    return remote_ref.removeprefix("refs/remotes/").partition("/")[2]


def _checkout_or_switch(sub: str, rest: list[str], _doc: str) -> list[str]:
    creators = {"-b", "-B", "-c", "-C", "--orphan", "--create", "--force-create"}
    flags, operands, values = parse(rest, CHECKOUT if sub == "checkout" else SWITCH)
    named = [value for name, value in values if name in creators]
    if not named and flags & {"-t", "--track"} and operands:
        return [_tracked_name(operands[0])]
    return named


def _worktree(_sub: str, rest: list[str], _doc: str) -> list[str]:
    """`worktree add -b x` creates x; with no -b and no --detach, git names the new branch after the path."""
    if rest[:1] != ["add"]:
        return []
    flags, operands, values = parse(rest[1:], WORKTREE)
    named = [value for name, value in values if name in ("-b", "-B")]
    automatic = not named and not flags & {"-d", "--detach"} and (len(operands) == 1 or "--orphan" in flags)
    return named + ([operands[0].rstrip("/").rsplit("/", 1)[-1]] if automatic and operands else [])


def _push_or_fetch(sub: str, rest: list[str], _doc: str) -> list[str]:
    spec = PUSH if sub == "push" else FETCH
    flags, operands, _ = parse(rest, spec)
    if flags & spec.skip:
        return []
    found, specs = [], iter(operands[1:])
    for ref in specs:
        if ref == "tag" and sub != "push":
            found.append(f"refs/tags/{next(specs, '')}")
        else:
            found.append(_refspec_destination(ref, needs_colon=sub != "push"))
    return [ref for ref in found if ref and ref != "refs/tags/"]


def _stash(_sub: str, rest: list[str], _doc: str) -> list[str]:
    return rest[1:2] if rest[:1] == ["branch"] else []


def _symbolic_ref(_sub: str, rest: list[str], _doc: str) -> list[str]:
    flags, operands, _ = parse(rest, SYMBOLIC_REF)
    return [] if flags & SYMBOLIC_REF.skip else operands[1:2]


def _update_ref(_sub: str, rest: list[str], doc: str) -> list[str]:
    flags, operands, _ = parse(rest, UPDATE_REF)
    if "--stdin" in flags:
        lines = (line.split() for line in doc.splitlines())
        return [words[1] for words in lines if len(words) > 1 and words[0] in ("create", "update")]
    return [] if flags & UPDATE_REF.skip else operands[:1]


_READERS = {
    "branch": _branch_or_tag,
    "tag": _branch_or_tag,
    "checkout": _checkout_or_switch,
    "switch": _checkout_or_switch,
    "worktree": _worktree,
    "push": _push_or_fetch,
    "fetch": _push_or_fetch,
    "pull": _push_or_fetch,
    "stash": _stash,
    "symbolic-ref": _symbolic_ref,
    "update-ref": _update_ref,
}


def created_refs(sub: str, rest: list[str], doc: str) -> list[str]:
    """Every ref name `git <sub> <rest...>` would create or point somewhere new; the heredoc feeds --stdin."""
    reader = _READERS.get(sub)
    return reader(sub, rest, doc) if reader else []
