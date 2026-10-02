"""What one git command line does to hooks through config: hooksPath, includes, aliases, other repositories, plumbing."""

import os
import re
from itertools import pairwise

from .flags import HOOK_SUBS

HOOKS_KEY = "core.hookspath"
GIT_VALUE = frozenset(
    ("-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix", "--config-env")
)
# Another repository's hooks (none) run for a commit made through it; a config file can carry core.hooksPath,
# and HOME / XDG_CONFIG_HOME move the global one.
OTHER_REPO_ENV = ("GIT_DIR", "GIT_COMMON_DIR")
CONFIG_FILE_ENV = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG", "HOME", "XDG_CONFIG_HOME")
INCLUDE_KEY = re.compile(r"include\.path|includeif\..*\.path", re.IGNORECASE)
# help.autocorrect runs a mistyped subcommand as the one it guesses, which no table here can read.
ASK_KEYS = re.compile(r"include\.path|includeif\..*\.path|help\.autocorrect", re.IGNORECASE)
PLUMBING = frozenset(("commit-tree", "update-ref", "fast-import", "send-pack"))
THIS_REPO = frozenset((".git", "./.git", "$PWD/.git", "${PWD}/.git", "$(pwd)/.git"))
UNSETTING = frozenset(("--unset", "--unset-all", "unset"))
READING = frozenset(("--get", "--get-all", "--get-regexp", "-l", "--list", "--remove-section", *UNSETTING))
READ_VERBS = frozenset(("get", "list", "unset", "remove-section", "rename-section", "edit"))
_COUNT = re.compile(r"\s*\+?(\d+)")  # git reads GIT_CONFIG_COUNT with strtoul: blanks and a + sign are accepted


def config_pairs(conf: list[str], env: dict[str, str]) -> list[tuple[str, str]]:
    """(key, value) set for one git command by -c/--config-env, GIT_CONFIG_COUNT/KEY_n/VALUE_n or GIT_CONFIG_PARAMETERS."""
    pairs = [(key, value) for key, _, value in (item.partition("=") for item in conf if "=" in item)]
    count = _COUNT.match(env.get("GIT_CONFIG_COUNT", ""))
    for i in range(min(int(count.group(1)), 64) if count else 0):
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


def unsets_hooks(rest: list[str]) -> bool:
    """`git config --unset core.hooksPath`: for husky and other managers that install through hooksPath, an uninstall."""
    return bool(UNSETTING & set(rest)) and any(arg.lower() == HOOKS_KEY for arg in rest)


def this_repo(path: str) -> bool:
    path = path.rstrip("/")
    return path in THIS_REPO or path == os.path.join(os.getcwd(), ".git")


def git_dirs(args: list[str], env: dict[str, str]) -> list[str]:
    """Repository paths a git command is pointed at by --git-dir or GIT_DIR/GIT_COMMON_DIR, other than this one's."""
    found, i = [env[name] for name in OTHER_REPO_ENV if name in env], 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "--git-dir" and i + 1 < len(args):
            found.append(args[i + 1])
        elif args[i].startswith("--git-dir="):
            found.append(args[i].split("=", 1)[1])
        i += 2 if args[i] in GIT_VALUE else 1
    return [path for path in found if not this_repo(path)]


def submodule_scripts(sub: str, rest: list[str]) -> list[str]:
    """The command `git submodule foreach` runs in each submodule."""
    if sub != "submodule" or "foreach" not in rest:
        return []
    words = rest[rest.index("foreach") + 1 :]
    while words and words[0] in ("--recursive", "-q", "--quiet"):
        words = words[1:]
    return [" ".join(words)] if words else []


def aliases(pairs: list[tuple[str, str]], env: dict[str, str]) -> dict[str, list[str]]:
    """alias name -> the texts it may run (the value, and for --config-env the variable's value); `!` marks a shell command."""
    found: dict[str, list[str]] = {}
    for key, value in pairs:
        if key.startswith("alias.") and value:
            found.setdefault(key[6:], []).extend(text for text in (value, env.get(value, "")) if text)
    return found


def asks_for(sub: str, rest: list[str], args: list[str], env: dict[str, str], pairs: list[tuple[str, str]]) -> str:
    """Why one git command needs a person's confirmation (plumbing, another repo, a config file), or ''."""
    keys = [key for key, _ in [*pairs, *(config_writes(rest) if sub == "config" else [])] if ASK_KEYS.fullmatch(key)]
    hooked = sub in HOOK_SUBS
    others = git_dirs(args, env) if hooked else []
    files = [name for name in CONFIG_FILE_ENV if name in env] if hooked else []
    reasons = (
        (
            sub in PLUMBING and not ({"-d", "--delete"} & set(rest)),
            f"git {sub} writes commits or refs without running any hook",
        ),
        (sub == "config" and unsets_hooks(rest), "unsetting core.hooksPath uninstalls hooks a manager put there"),
        (bool(keys), f"git {sub} with {''.join(keys[:1])} runs config or commands this guard cannot read"),
        (
            bool(others),
            f"git {sub} against another repository ({''.join(others[:1])}) runs that repository's hooks, not these",
        ),
        (bool(files), f"git {sub} with {''.join(files[:1])} reads a config file that can set core.hooksPath"),
    )
    return next((f"{reason}; a person must confirm it." for hit, reason in reasons if hit), "")


def env_asks(env: dict[str, str]) -> str:
    """Why variables left set for later git commands need a person: another repository or another config file."""
    if others := [name for name in OTHER_REPO_ENV if name in env and not this_repo(env[name])]:
        return (
            f"{others[0]} left set points later git commands at another repository's hooks; a person must confirm it."
        )
    if files := [name for name in CONFIG_FILE_ENV if name in env and name not in ("HOME",)]:
        return f"{files[0]} left set makes later git commands read a config file that can set core.hooksPath; a person must confirm it."
    return ""
