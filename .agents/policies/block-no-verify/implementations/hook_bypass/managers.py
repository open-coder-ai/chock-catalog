"""Hook managers' own off switches (husky, lefthook, pre-commit), their uninstall commands, and spellings the lexer drops."""

import re
import shlex
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
SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "fish"))
DECLARERS = frozenset(("declare", "typeset", "readonly", "local", "make", "gmake"))
PS_SETTERS = frozenset(("set-item", "si", "new-item", "ni", "set-content", "sc", "add-content", "ac"))
PYTHON = re.compile(r"python[\d.]*", re.IGNORECASE)
PS_PATH = re.compile(r"env:/?(\w+)$", re.IGNORECASE)
# PowerShell `$env:NAME = v` for the variables read here, rewritten to the NAME=v the lexer knows.
WATCHED = r"HUSKY\w*|LEFTHOOK\w*|SKIP|PRE_COMMIT_ALLOW_NO_CONFIG|GIT_\w+|HOME|XDG_CONFIG_HOME"
PS_ASSIGN = re.compile(rf"\$\{{?env:({WATCHED})\}}?\s*[+.]?=\s*", re.IGNORECASE)
DOTNET_SET = re.compile(
    rf"\[(?:System\.)?Environment\]::SetEnvironmentVariable\(\s*['\"]({WATCHED})['\"]\s*,\s*['\"]?([^'\",)]*)['\"]?[^)]*\)",
    re.IGNORECASE,
)
# bash ANSI-C ($'..') and locale ($"..") quoting: the shell hands the program the plain text.
ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.DOTALL)
LOCALE = re.compile(r'\$"((?:[^"\\]|\\.)*)"', re.DOTALL)
ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|u[0-9a-fA-F]{1,4}|.)", re.DOTALL)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v"}
HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][\w.-]*)\1")
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


def program(word: str) -> str:
    """A word as the program it names: path, .exe and a version or extras spec dropped (pre-commit==3.7 is pre-commit)."""
    return re.sub(r"(@.*|==.*|\[.*|\.exe)$", "", word.replace("\\", "/").rsplit("/", 1)[-1].lower())


def launched(name: str, args: list[str]) -> list[str]:
    """What a launcher (npx, pnpm exec, uv run, pipx run, python -m ...) runs, from the first word that is git, a
    shell or a hook manager, so a launcher option's value cannot hide it; [] when the command is no launcher or runs neither."""
    if not (name.lower() in LAUNCHERS or PYTHON.fullmatch(name)):
        return []
    at = next((i for i, word in enumerate(args) if program(word) in MANAGERS | SHELLS | {"git"}), -1)
    return [program(args[at]), *args[at + 1 :]] if at >= 0 else []


def uninstalls(name: str, args: list[str]) -> str:
    """`pre-commit|lefthook|husky uninstall`, also behind a launcher; else ''."""
    words = launched(name, args) or [program(name), *args]
    return f"{words[0]} uninstall" if words[0] in MANAGERS and "uninstall" in words[1:] else ""


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
    text = DOTNET_SET.sub(lambda m: f"{m.group(1).upper()}={shlex.quote(m.group(2))}", text)
    return PS_ASSIGN.sub(lambda m: f"{m.group(1).upper()}=", text)


def without_bodies(text: str) -> str:
    """The line with here-document bodies dropped: a body is input to a program, not shell syntax, so an apostrophe
    in a commit message read from one does not make the line unparsed. A marker inside quotes is not a marker."""
    out: list[str] = []
    pending: list[str] = []
    for line in text.split("\n"):
        if pending:
            pending = pending[1:] if line.strip("\t") == pending[0] else pending
            continue
        out.append(line)
        pending += [m.group(2) for m in HEREDOC.finditer(line) if _unquoted(line[: m.start()])]
    return "\n".join(out)


def _unquoted(before: str) -> bool:
    return before.count("'") % 2 == 0 and before.count('"') % 2 == 0
