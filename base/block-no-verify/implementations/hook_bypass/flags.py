"""The hook-skip option on one git subcommand, read with that subcommand's own options (stdlib only)."""

import re

# Subcommands that run hooks or take the hook-skip long option (cherry-pick and revert: refused as an attempt
# even where git rejects the option, so a newer git accepting it changes nothing here).
HOOK_SUBS = frozenset(("commit", "push", "merge", "am", "rebase", "pull", "cherry-pick", "revert"))
SHORT_N_SUBS = frozenset(("commit", "am"))  # merge/pull/rebase read -n as --no-stat, push as --dry-run
PREFIX_FLOOR = 9  # --no-veri: shorter collides with --no-verbose
_PICK = "-m --mainline -s -X --strategy --strategy-option --cleanup"
# Per subcommand: options whose value is the NEXT word, and short letters whose value is the rest of a cluster.
# Only options git documents as taking a value are listed; an unknown option is read as a flag, so the word
# after it is still judged (an error toward refusing).
_OPTIONS = {
    "commit": (
        "-m -F -C -c -t --message --file --author --date --template --fixup --squash --reuse-message"
        " --reedit-message --cleanup --trailer --pathspec-from-file",
        "mFCctSu",
    ),
    "merge": ("-m -F -s -X --message --file --strategy --strategy-option --into-name --cleanup", "mFsXS"),
    "pull": (
        "-s -X -o --strategy --strategy-option --depth --shallow-since --shallow-exclude --upload-pack --server-option",
        "sXoS",
    ),
    "push": ("-o --push-option --repo --receive-pack --exec", "o"),
    "am": ("-p --directory --exclude --include --patch-format --resolvemsg", "pSC"),
    "rebase": ("-s -X -x --strategy --strategy-option --onto --exec", "sXxSC"),
    "cherry-pick": (_PICK, "msXS"),
    "revert": (_PICK, "msXS"),
}
TAKES_VALUE = {sub: frozenset(words.split()) for sub, (words, _) in _OPTIONS.items()}
VALUE_LETTERS = {sub: letters for sub, (_, letters) in _OPTIONS.items()}
_BRACE = re.compile(r"\{([^{}]*,[^{}]*)\}")
_MAX_WORDS = 64


def expand(word: str) -> list[str]:
    """Bash brace expansion of an unquoted word: `x{--a,}` gives `x--a` and `x`."""
    match = _BRACE.search(word)
    if match is None:
        return [word]
    parts = [word[: match.start()] + part + word[match.end() :] for part in match.group(1).split(",")]
    return [found for part in parts for found in expand(part)][:_MAX_WORDS]


def is_no_verify(arg: str) -> bool:
    """--no-verify or any unambiguous prefix of it, down to git's floor."""
    return len(arg) >= PREFIX_FLOOR and "--no-verify".startswith(arg)


def cluster(sub: str, arg: str) -> tuple[str, bool]:
    """A short-option cluster read letter by letter: (letters that are flags, whether its last letter takes the next word)."""
    letters = VALUE_LETTERS.get(sub, "")
    for i, char in enumerate(arg[1:], start=1):
        if char in letters:
            return arg[1:i], i == len(arg) - 1
    return arg[1:], False


def skips_verify(sub: str, rest: list[str]) -> bool:
    """The hook-skip long option on a hook-running subcommand; a short -n only where it means that."""
    skip = False
    for raw in rest:
        if raw == "--":
            break
        if skip:
            skip = False
            continue
        for arg in expand(raw):
            short = arg[:1] == "-" and arg[1:2] not in ("-", "")
            flags, skip = cluster(sub, arg) if short else ("", arg in TAKES_VALUE.get(sub, ()))
            if is_no_verify(arg) or (sub in SHORT_N_SUBS and "n" in flags):
                return True
    return False


def rebase_execs(rest: list[str]) -> list[str]:
    """Commands `git rebase` runs after each pick: -x/--exec and git's accepted prefixes (--ex, --exe), clustered (-ix)."""
    found, take = [], False
    for arg in rest:
        if take:
            found.append(arg)
            take = False
            continue
        name, eq, value = arg.partition("=")
        if len(name) >= 4 and "--exec".startswith(name):  # noqa: PLR2004 -- --ex: --e is ambiguous with --empty
            found += [value] if eq else []
            take = not eq
        elif arg[:1] == "-" and arg[1:2] not in ("-", ""):
            at = next((i for i, char in enumerate(arg[1:], start=1) if char in VALUE_LETTERS["rebase"]), 0)
            if at and arg[at] == "x":
                found += [arg[at + 1 :]] if at + 1 < len(arg) else []
                take = at + 1 == len(arg)
    return found
