"""Match one parsed command against the table's rules: which program it really runs, its verb, its flags."""

import re

from chock_shellparse import Cmd, flags_of, operands, positionals

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


def hop(name: str, args: list[str], launchers: list[str]) -> tuple[str, list[str]] | None:
    """The program behind a python -m, shell script or npx-style launcher, or None when `name` is what runs."""
    if name.startswith("python") and "-m" in args[:-1]:
        at = args.index("-m")
        return args[at + 1].lower(), args[at + 2 :]
    if name in SHELLS or name in launchers:
        rest = operands(args)
        if rest:
            return rest[0].replace("\\", "/").rsplit("/", 1)[-1].lower(), args[args.index(rest[0]) + 1 :]
    return None


def resolve(cmd: Cmd, launchers: list[str]) -> tuple[str, list[str]]:
    name, args = cmd.name, cmd.args
    for _ in range(HOPS):
        step = hop(name, args, launchers)
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
    """npm-style dry run: the last --dry-run option wins and --dry-run=false turns it off."""
    last = [arg for arg in args if arg.split("=", 1)[0] == "--dry-run"]
    return bool(last) and last[-1].partition("=")[2].lower() in ("", "true", "1")


def verb_at(rule: dict, pos: list[str], heads: set[str]) -> tuple[list[str], int] | None:
    """(phrase of `rule`, where it ends in `pos`) once leading unknown words are skipped, or None."""
    start = next((i for i, word in enumerate(pos) if word in heads), len(pos))
    for phrase in rule["verbs"]:
        if not phrase or pos[start : start + len(phrase)] == phrase:
            return phrase, start + len(phrase)
    return None


def judge(cmd: Cmd, tab: dict) -> tuple[str, str] | None:
    """(level, reason) of the first rule this command matches, or None."""
    name, args = resolve(cmd, tab["launchers"])
    bare = name.removesuffix(".cmd").removesuffix(".bat")
    pos = [word.lower() for word in positionals(args, frozenset(tab["value_flags"].get(bare, ())))]
    for rule in tab["rules"]:
        if name not in rule["prog"] and bare not in rule["prog"]:
            continue
        heads = {phrase[0] for phrase in rule["verbs"] if phrase} | set(tab["stops"])
        found = verb_at(rule, pos, heads)
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
