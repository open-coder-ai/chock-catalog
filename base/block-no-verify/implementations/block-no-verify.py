#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse git commit/push --no-verify and the other ways of switching git hooks off.

import os
import re
import shlex
import sys

from chock_shellparse import commands, git_parts

HOOKS_KEY = "core.hookspath"
# git commit options whose value is the NEXT argument: a message that starts with -n is not a flag.
TAKES_VALUE = frozenset(
    ("-m", "-F", "-C", "-c", "-t", "--message", "--file", "--author", "--date", "--template", "--fixup", "--squash")
)
PREFIX_FLOOR = 9
# A short cluster starting with one of these carries that option's value: `-mnote` is a message.
VALUE_CLUSTER = ("-m", "-F", "-u", "-C", "-c", "-S")


def hooks_path_keys(conf: list[str], env: dict[str, str]) -> list[str]:
    """Config keys set for one git command by -c/--config-env, GIT_CONFIG_COUNT/KEY_n or GIT_CONFIG_PARAMETERS."""
    keys = [item.split("=", 1)[0] for item in conf if "=" in item]
    count = env.get("GIT_CONFIG_COUNT", "")
    keys += [env.get(f"GIT_CONFIG_KEY_{i}", "") for i in range(min(int(count), 64) if count.isdigit() else 0)]
    keys += re.findall(r"'([^'=]+)'?=", env.get("GIT_CONFIG_PARAMETERS", ""))
    return [key.lower() for key in keys]


def config_sets_hooks(rest: list[str]) -> bool:
    """`git config core.hooksPath <value>` in any scope; reading or unsetting it is not a bypass."""
    operands = [arg for arg in rest if not arg.startswith("-")]
    reading = {"--get", "--get-all", "--get-regexp", "-l", "--list", "--unset", "--unset-all"} & set(rest)
    at = [i for i, arg in enumerate(operands) if arg.lower() == HOOKS_KEY]
    return bool(at) and not reading and at[0] + 1 < len(operands)


def is_no_verify(arg: str) -> bool:
    """--no-verify or any unambiguous prefix of it; git's floor is --no-veri (shorter collides with --no-verbose)."""
    return len(arg) >= PREFIX_FLOOR and "--no-verify".startswith(arg)


def is_short_n(arg: str) -> bool:
    """A short cluster containing -n, unless it starts with an option whose attached text is a value."""
    return re.fullmatch(r"-[^-].*", arg) is not None and "n" in arg and not arg.startswith(VALUE_CLUSTER)


def skips_verify(sub: str, rest: list[str]) -> bool:
    """--no-verify on commit or push; a short -n only on commit, where on push it means --dry-run."""
    skip = False
    for arg in rest:
        if arg == "--":
            break
        if skip:
            skip = False
        elif is_no_verify(arg) or (sub == "commit" and is_short_n(arg)):
            return True
        else:
            skip = arg in TAKES_VALUE
    return False


def check(raw: str) -> str | None:
    """The reason a command switches hooks off, or None."""
    for cmd in commands(raw):
        if cmd.name != "git":
            continue
        sub, conf, rest = git_parts(cmd.args)
        if sub == "config" and config_sets_hooks(rest):
            return "git config core.hooksPath disables every hook, exactly as --no-verify does. Fix the failing hook instead."
        if sub not in ("commit", "push"):
            continue
        if HOOKS_KEY in hooks_path_keys(conf, cmd.env):
            return f"git {sub} with core.hooksPath set disables every hook, exactly as --no-verify does. Fix the failing hook instead of routing around it."
        if skips_verify(sub, rest):
            return f"git {sub} --no-verify is not allowed. Fix the hook failure instead."
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-no-verify: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
