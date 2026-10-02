"""Hook managers' own off switches (husky, lefthook, pre-commit), their uninstall commands, and spellings the lexer drops."""

import re
from itertools import pairwise

# Each variable makes the hook manager skip its hooks (HUSKY/LEFTHOOK only when not 1/true; the rest when non-empty).
HOOK_ENV = frozenset(
    (
        "HUSKY",
        "HUSKY_SKIP_HOOKS",
        "LEFTHOOK",
        "LEFTHOOK_EXCLUDE",
        "LEFTHOOK_CONFIG",
        "SKIP",
        "PRE_COMMIT_ALLOW_NO_CONFIG",
    )
)
ON_SWITCHES = frozenset(("HUSKY", "LEFTHOOK"))
MAKE_ENV = HOOK_ENV - {"SKIP"}  # `make test SKIP=slow` is an ordinary make variable far more often than pre-commit's
MANAGERS = frozenset(("pre-commit", "pre_commit", "lefthook", "husky"))
LAUNCHERS = frozenset(
    (
        *("npx", "pnpx", "bunx", "uvx", "pipx", "yarn", "pnpm", "npm", "bun", "uv", "poetry", "pdm", "hatch", "rye"),
        *("python", "python3", "py", "node", "exec", "dlx", "run", "x", "tool"),
    )
)
DECLARERS = frozenset(("declare", "typeset", "readonly", "local", "make", "gmake"))
PS_SETTERS = frozenset(("set-item", "si", "new-item", "ni", "set-content", "sc", "add-content", "ac"))
PYTHON = re.compile(r"python[\d.]*", re.IGNORECASE)
PS_PATH = re.compile(r"env:/?(\w+)$", re.IGNORECASE)
# PowerShell `$env:NAME = v` for the variables read here, rewritten to the NAME=v the lexer knows.
WATCHED = r"HUSKY\w*|LEFTHOOK\w*|SKIP|PRE_COMMIT_ALLOW_NO_CONFIG|GIT_\w+|HOME|XDG_CONFIG_HOME"
PS_ASSIGN = re.compile(rf"\$\{{?env:({WATCHED})\}}?\s*[+.]?=\s*", re.IGNORECASE)
# bash ANSI-C ($'..') and locale ($"..") quoting: the shell hands the program the plain text.
ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.DOTALL)
LOCALE = re.compile(r'\$"((?:[^"\\]|\\.)*)"', re.DOTALL)
ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|u[0-9a-fA-F]{1,4}|.)", re.DOTALL)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v"}
END = "chock_end_of_line"  # a final command whose environment is what the line leaves set for later commands


def disables(name: str, value: str) -> bool:
    """True when NAME=value switches a hook manager off (names compared as written: POSIX variables are case-sensitive)."""
    if name not in HOOK_ENV or value == "":
        return False
    return name not in ON_SWITCHES or value.strip("'\"").lower() not in ("1", "true")


def env_hits(env: dict[str, str]) -> list[str]:
    return [f"{name}={value}" for name, value in env.items() if disables(name, value)]


def declared(name: str, args: list[str]) -> dict[str, str]:
    """NAME -> value written by declare/typeset/make, fish or cmd `set`, setx/setenv and PowerShell Set-Item Env:."""
    pairs = [(key, value) for key, _, value in (arg.partition("=") for arg in args if "=" in arg)]
    pairs = pairs if name in DECLARERS or name == "set" else []
    if name in ("set", "setx", "setenv"):  # cmd and Windows names are case-insensitive
        operands = [arg for arg in args if not arg.startswith(("-", "/"))]
        pairs = [(key.upper(), value) for key, value in pairs]
        pairs += [(key.upper(), value) for key, value in pairwise(operands) if "=" not in key]
    if name in PS_SETTERS:
        pairs += [
            (m.group(1).upper(), (args[i + 1 :] or ["1"])[0]) for i, a in enumerate(args) if (m := PS_PATH.search(a))
        ]
    if name in ("make", "gmake"):
        pairs = [(key, value) for key, value in pairs if key in MAKE_ENV]
    return {key: value or "1" for key, value in pairs}


def launched(name: str, args: list[str]) -> list[str]:
    """The command a launcher runs (npx, pnpm exec, uv run, pipx run, python -m ...), as words; [] when none."""
    words = [name, *args]
    while words and (words[0].lower() in LAUNCHERS or PYTHON.fullmatch(words[0]) or words[0].startswith("-")):
        words = words[1:]
    return words if len(words) <= len(args) else []


def uninstalls(name: str, args: list[str]) -> str:
    """`pre-commit|lefthook|husky uninstall`, also behind a launcher; else ''."""
    words = launched(name, args) or [name, *args]
    tool = re.sub(r"(@.*|\.exe)$", "", words[0].replace("\\", "/").rsplit("/", 1)[-1].lower())
    return f"{tool} uninstall" if tool in MANAGERS and "uninstall" in words[1:] else ""


def _unescape(code: str) -> str:
    if code[0] in "xu" and len(code) > 1:
        return chr(int(code[1:], 16))
    if code[0] in "01234567":
        return chr(int(code, 8))
    return _ESCAPES.get(code, code)


def _ansi(match: re.Match[str]) -> str:
    """$'..' decoded to the text bash passes on, re-quoted as a plain single-quoted word."""
    text = ESCAPE.sub(lambda m: _unescape(m.group(1)), match.group(1))
    return "'" + text.replace("'", "'\\''") + "'"


def normalise(text: str) -> str:
    """Spellings the lexer does not read, rewritten to ones it does; quoted text stays data either way."""
    text = LOCALE.sub(lambda m: f'"{m.group(1)}"', ANSI_C.sub(_ansi, text))
    return PS_ASSIGN.sub(lambda m: f"{m.group(1).upper()}=", text)
