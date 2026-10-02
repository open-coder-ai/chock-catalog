"""Match one parsed command against the table's rules: which program it really runs, its verb, its flags."""

import re

from chock_shellparse import Cmd, flags_of

PINNED = re.compile(r"(?<=.)(?:@|==)[^/@=]*$")

SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh"))
HOPS = 3


def value_of(args: list[str], *flags: str) -> str:
    """The lowercased value of `--flag value`, `--flag=value` or `-fvalue`, or ''."""
    for i, arg in enumerate(args):
        for flag in flags:
            if arg == flag and i + 1 < len(args):
                return args[i + 1].lower()
            if arg.startswith(flag + "=") or (
                not flag.startswith("--") and arg.startswith(flag) and len(arg) > len(flag)
            ):
                return arg[len(flag) :].lstrip("=").lower()
    return ""


def indexes(args: list[str], value_flags: frozenset[str]) -> list[int]:
    """Where the operands are in `args`, leaving out options and the values of `value_flags`."""
    found, skip = [], False
    for i, arg in enumerate(args):
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in value_flags
        else:
            found.append(i)
    return found


def program(word: str) -> str:
    """A command word as a program name: last path part, lowercased, a pinned `@version` dropped."""
    return PINNED.sub("", word.replace("\\", "/").rsplit("/", 1)[-1].lower())


def hop(name: str, args: list[str], tab: dict, *, eager: bool) -> tuple[str, list[str]] | None:
    """The program behind a python -m, shell script, npx-style launcher or `npm exec`, or None when `name` runs."""
    if name.startswith("python") and "-m" in args[:-1]:
        at = args.index("-m")
        return args[at + 1].lower(), args[at + 2 :]
    where = indexes(args, frozenset(tab["value_flags"].get(name, ())))
    loose = bool(where) and where[0] > 0 and args[where[0] - 1].startswith("-")
    runner = [] if loose and not eager else tab["runners"].get(name, ())
    words = next((w.split() for w in runner if [args[i] for i in where[: len(w.split())]] == w.split()), [])
    if words:
        where = where[len(words) :]
    elif name not in SHELLS and name not in tab["launchers"]:
        return None
    return (program(args[where[0]]), args[where[0] + 1 :]) if where else None


def resolve(cmd: Cmd, tab: dict, *, eager: bool) -> tuple[str, list[str]]:
    """The program a command runs through launchers; `eager` reads a word after any option as a runner word."""
    name, args = cmd.name, cmd.args
    for _ in range(HOPS):
        step = hop(name, args, tab, eager=eager)
        if step is None:
            break
        name, args = step
    return name, args


def holds(when: dict, args: list[str]) -> bool:
    """Whether any of the rule's conditions is present (no `when` always holds)."""
    if not when:
        return True
    flags = flags_of(args)
    if flags & set(when.get("flags", ())):
        return True
    if any(value_of(args, flag) in values for flag, values in when.get("values", {}).items()):
        return True
    pattern = when.get("arg_regex")
    return bool(pattern) and any(re.search(pattern, arg.replace("\\", "/")) for arg in args)


def dry_run(args: list[str]) -> bool:
    """npm-style dry run: the last of --dry-run[=value] and --no-dry-run wins; words after `--` are operands."""
    state = False
    for arg in args:
        key, _, value = arg.partition("=")
        if arg == "--":
            break
        if key in ("--dry-run", "--no-dry-run"):
            state = key == "--dry-run" and value.lower() in ("", "true", "1")
    return state


def verb_at(rule: dict, pos: list[str], heads: set[str], loose: list[bool]) -> tuple[list[str], int] | None:
    """(phrase of `rule`, where it ends in `pos`) once leading unknown words are skipped, or None.

    A word right after an option the table does not know may be that option's value, so only the
    rule's own verbs (not the table's stop words) anchor there.
    """
    own = {phrase[0] for phrase in rule["verbs"] if phrase}
    start = next((i for i, word in enumerate(pos) if word in own or (word in heads and not loose[i])), len(pos))
    for phrase in rule["verbs"]:
        if not phrase or pos[start : start + len(phrase)] == phrase:
            return phrase, start + len(phrase)
    return None


def judge(cmd: Cmd, tab: dict) -> tuple[str, str] | None:
    """(level, reason) of the first rule this command matches, or None; both readings of a runner word are tried."""
    for eager in (False, True):
        found = match(*resolve(cmd, tab, eager=eager), tab)
        if found:
            return found
    return None


def match(name: str, args: list[str], tab: dict) -> tuple[str, str] | None:
    bare = name.removesuffix(".cmd").removesuffix(".bat")
    where = indexes(args, frozenset(tab["value_flags"].get(bare, ())))
    pos = [args[i].lower() for i in where]
    loose = [i > 0 and args[i - 1].startswith("-") for i in where]
    if "--help" in args or "-h" in args:
        return None
    for rule in tab["rules"]:
        if name not in rule["prog"] and bare not in rule["prog"]:
            continue
        heads = {phrase[0] for phrase in rule["verbs"] if phrase} | set(tab["stops"])
        found = verb_at(rule, pos, heads, loose)
        if found is None or not holds(rule.get("when", {}), args):
            continue
        phrase, end = found
        if flags_of(args) & set(rule.get("unless", ())) or (rule.get("dry_run") and dry_run(args)):
            continue
        key = rule.get("config_key")
        if key and not re.search(key, (pos[end:] or [""])[0].split("=")[0]):
            continue
        return rule["level"], f"{' '.join([name, *phrase])}: {rule['why']}"
    return None
