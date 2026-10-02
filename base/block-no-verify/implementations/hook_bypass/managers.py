"""Hook managers' own off switches: husky, lefthook and pre-commit variables, and their uninstall commands."""

import re
from itertools import pairwise

# Each variable makes the hook manager skip its hooks (HUSKY/LEFTHOOK only when not 1/true; the rest when non-empty).
HOOK_ENV = frozenset(
    ("HUSKY", "HUSKY_SKIP_HOOKS", "LEFTHOOK", "LEFTHOOK_EXCLUDE", "SKIP", "PRE_COMMIT_ALLOW_NO_CONFIG")
)
ON_SWITCHES = frozenset(("HUSKY", "LEFTHOOK"))
MANAGERS = frozenset(("pre-commit", "pre_commit", "lefthook", "husky"))
LAUNCHERS = frozenset(
    (
        *("npx", "pnpx", "bunx", "uvx", "pipx", "yarn", "pnpm", "npm", "bun", "uv", "poetry", "pdm", "hatch", "rye"),
        *("python", "python3", "py", "node", "exec", "dlx", "run", "x", "tool"),
    )
)
DECLARERS = frozenset(("declare", "typeset", "readonly", "local", "make", "gmake"))
PS_SETTERS = frozenset(("set-item", "si", "new-item", "ni", "set-content", "sc", "add-content", "ac"))
PS_ASSIGN = re.compile(rf"\$\{{?env:({'|'.join(sorted(HOOK_ENV))})\}}?\s*[+.]?=\s*", re.IGNORECASE)
PYTHON = re.compile(r"python[\d.]*", re.IGNORECASE)
PS_PATH = re.compile(r"env:/?(\w+)$", re.IGNORECASE)
END = "chock_end_of_line"  # a final command whose environment is what the line leaves set for later commands


def disables(name: str, value: str) -> bool:
    """True when NAME=value switches a hook manager off (names compared as written: POSIX variables are case-sensitive)."""
    if name not in HOOK_ENV or value == "":
        return False
    return name not in ON_SWITCHES or value.strip("'\"").lower() not in ("1", "true")


def env_hits(env: dict[str, str]) -> list[str]:
    return [f"{name}={value}" for name, value in env.items() if disables(name, value)]


def declared(name: str, args: list[str]) -> list[str]:
    """NAME=value pairs written by declare/typeset/make, fish or cmd `set`, setx/setenv and PowerShell Set-Item Env:."""
    pairs: list[tuple[str, str]] = []
    if name in DECLARERS or name == "set":
        pairs += [(key, value) for key, _, value in (arg.partition("=") for arg in args if "=" in arg)]
    if name in ("set", "setx", "setenv"):
        operands = [arg for arg in args if not arg.startswith(("-", "/"))]
        pairs += [(key.upper(), value) for key, value in pairwise(operands)]
    if name in PS_SETTERS:
        pairs += [
            (m.group(1).upper(), args[i + 1] if i + 1 < len(args) else "1")
            for i, a in enumerate(args)
            if (m := PS_PATH.search(a))
        ]
    return [f"{key}={value}" for key, value in pairs if disables(key, value or "1")]


def uninstalls(name: str, args: list[str]) -> str:
    """`pre-commit|lefthook|husky uninstall`, also behind npx, pnpm exec, uvx, pipx run or python -m; else ''."""
    words = [name, *args]
    while words and (words[0].lower() in LAUNCHERS or PYTHON.fullmatch(words[0]) or words[0].startswith("-")):
        words = words[1:]
    if not words:
        return ""
    tool = re.sub(r"(@.*|\.exe)$", "", words[0].replace("\\", "/").rsplit("/", 1)[-1].lower())
    return f"{tool} uninstall" if tool in MANAGERS and "uninstall" in words[1:] else ""


def normalise(text: str) -> str:
    """PowerShell `$env:HUSKY = 0` rewritten to the HUSKY=0 the lexer reads; quoted text stays data either way."""
    return PS_ASSIGN.sub(lambda m: f"{m.group(1).upper()}=", text)
