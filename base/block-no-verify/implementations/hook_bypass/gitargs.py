"""What one git command line does to hooks: skip flags, hooksPath and include config, aliases, plumbing."""

import re
from itertools import pairwise

HOOKS_KEY = "core.hookspath"
# Subcommands that run hooks or take the hook-skip long option (cherry-pick and revert: refused as an attempt
# even where git rejects the option, so a newer git accepting it changes nothing here).
HOOK_SUBS = frozenset(("commit", "push", "merge", "am", "rebase", "pull", "cherry-pick", "revert"))
SHORT_N_SUBS = frozenset(("commit", "am"))  # merge/pull/rebase read -n as --no-stat, push as --dry-run
PREFIX_FLOOR = 9  # --no-veri: shorter collides with --no-verbose
# Options whose value is the NEXT argument: a message that starts with -n is not a flag.
TAKES_VALUE = frozenset(
    ("-m", "-F", "-C", "-c", "-t", "--message", "--file", "--author", "--date", "--template", "--fixup", "--squash")
)
# A short cluster starting with one of these carries that option's value: `-mnote` is a message.
VALUE_CLUSTER = ("-m", "-F", "-u", "-C", "-c", "-S")
GIT_VALUE = frozenset(("-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix"))
# Another repository's hooks (none) run for a commit made through it; a config file can carry core.hooksPath.
OTHER_REPO_ENV = ("GIT_DIR", "GIT_COMMON_DIR")
CONFIG_FILE_ENV = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG")
INCLUDE_KEY = re.compile(r"include\.path|includeif\..*\.path", re.IGNORECASE)
PLUMBING = frozenset(("commit-tree", "update-ref", "fast-import"))
THIS_REPO = frozenset((".git", "./.git"))
READING = frozenset(
    ("--get", "--get-all", "--get-regexp", "-l", "--list", "--unset", "--unset-all", "--remove-section")
)
READ_VERBS = frozenset(("get", "list", "unset", "remove-section", "rename-section", "edit"))


def config_pairs(conf: list[str], env: dict[str, str]) -> list[tuple[str, str]]:
    """(key, value) set for one git command by -c/--config-env, GIT_CONFIG_COUNT/KEY_n/VALUE_n or GIT_CONFIG_PARAMETERS."""
    pairs = [(key, value) for key, _, value in (item.partition("=") for item in conf if "=" in item)]
    count = env.get("GIT_CONFIG_COUNT", "")
    for i in range(min(int(count), 64) if count.isdigit() else 0):
        pairs.append((env.get(f"GIT_CONFIG_KEY_{i}", ""), env.get(f"GIT_CONFIG_VALUE_{i}", "")))
    params = env.get("GIT_CONFIG_PARAMETERS", "")
    pairs += re.findall(r"'([^'=]+)'='([^']*)'", params) + re.findall(r"'([^'=]+)=([^']*)'", params)
    pairs += [(key, "") for key in re.findall(r"'([^'=]+)'(?![='])", params)]
    return [(key.lower(), value) for key, value in pairs]


def config_writes(rest: list[str]) -> list[tuple[str, str]]:
    """(key, value) pairs a `git config [set] ...` call may write; a key is any operand followed by another. [] when it reads."""
    operands = [arg for arg in rest if not arg.startswith("-")]
    if READING & set(rest) or (operands[:1] and operands[0] in READ_VERBS):
        return []
    return [(key.lower(), value) for key, value in pairwise(operands)]


def is_no_verify(arg: str) -> bool:
    """--no-verify or any unambiguous prefix of it, down to git's floor."""
    return len(arg) >= PREFIX_FLOOR and "--no-verify".startswith(arg)


def is_short_n(arg: str) -> bool:
    """A short cluster containing -n, unless it starts with an option whose attached text is a value."""
    return re.fullmatch(r"-[^-].*", arg) is not None and "n" in arg and not arg.startswith(VALUE_CLUSTER)


def skips_verify(sub: str, rest: list[str]) -> bool:
    """--no-verify on a hook-running subcommand; a short -n only where it means that."""
    skip = False
    for arg in rest:
        if arg == "--":
            break
        if skip:
            skip = False
        elif is_no_verify(arg) or (sub in SHORT_N_SUBS and is_short_n(arg)):
            return True
        else:
            skip = arg in TAKES_VALUE
    return False


def git_dirs(args: list[str], env: dict[str, str]) -> list[str]:
    """Repository paths a git command is pointed at by --git-dir or GIT_DIR/GIT_COMMON_DIR, other than this one's."""
    found, i = [env[name] for name in OTHER_REPO_ENV if name in env], 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "--git-dir" and i + 1 < len(args):
            found.append(args[i + 1])
        elif args[i].startswith("--git-dir="):
            found.append(args[i].split("=", 1)[1])
        i += 2 if args[i] in GIT_VALUE or args[i] == "--config-env" else 1
    return [path for path in found if path.rstrip("/") not in THIS_REPO]


def nested_scripts(sub: str, rest: list[str]) -> list[str]:
    """Shell commands git itself runs: rebase -x/--exec, submodule foreach."""
    if sub == "rebase":
        found = [rest[i + 1] for i, arg in enumerate(rest[:-1]) if arg in ("-x", "--exec")]
        found += [arg.split("=", 1)[1] for arg in rest if arg.startswith("--exec=")]
        return found + [arg[2:] for arg in rest if arg.startswith("-x") and arg != "-x"]
    if sub == "submodule" and "foreach" in rest:
        words = rest[rest.index("foreach") + 1 :]
        while words and words[0] in ("--recursive", "-q", "--quiet"):
            words = words[1:]
        return [" ".join(words)] if words else []
    return []


def alias_scripts(pairs: list[tuple[str, str]], env: dict[str, str]) -> list[tuple[str, str]]:
    """(alias, command line it runs) for every alias.NAME defined here; a `!` alias is a shell command."""
    found = []
    for key, value in pairs:
        if key.startswith("alias.") and value:
            for text in {value, env.get(value, "")} - {""}:
                found.append((key[6:], text[1:] if text.startswith("!") else f"git {text}"))
    return found


def asks_for(sub: str, rest: list[str], args: list[str], env: dict[str, str], pairs: list[tuple[str, str]]) -> str:
    """Why one git command needs a person's confirmation (plumbing, another repo, a config file), or ''."""
    included = [key for key, _ in config_writes(rest) if INCLUDE_KEY.fullmatch(key)] if sub == "config" else []
    hooked = sub in HOOK_SUBS
    others = git_dirs(args, env) if hooked else []
    files = [name for name in CONFIG_FILE_ENV if name in env] if hooked else []
    reasons = (
        (
            sub in PLUMBING and not ({"-d", "--delete"} & set(rest)),
            f"git {sub} writes commits or refs without running any hook",
        ),
        (
            bool(included),
            f"git config {''.join(included[:1])} pulls in another config file, which can set core.hooksPath",
        ),
        (
            bool(others),
            f"git {sub} against another repository ({''.join(others[:1])}) runs that repository's hooks, not these",
        ),
        (bool(files), f"git {sub} with {''.join(files[:1])} reads a config file that can set core.hooksPath"),
        (
            hooked and any(INCLUDE_KEY.fullmatch(key) for key, _ in pairs),
            f"git {sub} with an include.path config pulls in a file that can set core.hooksPath",
        ),
    )
    return next((f"{reason}; a person must confirm it." for hit, reason in reasons if hit), "")
