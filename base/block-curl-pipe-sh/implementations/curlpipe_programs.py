"""Where an interpreter takes its program from: stdin, a -c/-e code argument, a script file, or a module."""

import re
from typing import NamedTuple

from chock_shellparse import Cmd, abbreviates

SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "posh", "fish", "csh", "tcsh"))
STDIN_PATHS = frozenset(("-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"))


class Family(NamedTuple):
    """How one interpreter family names its program: code flags, module flags, flags taking a value, code letters."""

    code: frozenset[str]
    module: frozenset[str] = frozenset()
    values: frozenset[str] = frozenset()
    letters: str = ""
    stops: str = ""


def _f(code: str, module: str = "", values: str = "", letters: str = "") -> Family:
    """`letters` is "code letters|letters that take the rest of the cluster as a value"."""
    code_letters, _, stops = letters.partition("|")
    return Family(frozenset(code.split()), frozenset(module.split()), frozenset(values.split()), code_letters, stops)


FAMILIES = {
    "python": _f("-c", "-m", "-W -X --check-hash-based-pycs"),
    "pypy": _f("-c", "-m", "-W -X"),
    "perl": _f("", "", "-I -M -m", "eE|IMmFixC0ld"),
    "ruby": _f("", "", "-I -r -C -E -F", "e|IrCEFxK0i"),
    "node": _f("-e --eval -p --print", "", "-r --require --import --loader -C --conditions"),
    "php": _f("-r -B -R -F -E", "", "-c -d -z"),
    "lua": _f("-e", "", "-l"),
    "osascript": _f("-e", "", "-l -s"),
    "rscript": _f("-e"),
    "r": _f("-e", "", "-f --file"),
    "julia": _f("-e --eval -E --print", "", "-L --load -p --procs -t --threads"),
    "tclsh": _f(""),
    "wish": _f(""),
    "sh": _f("", "", "-o +o -O +O --rcfile --init-file", "c|oO"),
}
_FAMILY = re.compile(r"(python|pypy|perl|ruby|node|php|lua|osascript|rscript|r|julia|tclsh|wish)(?:js|jit)?[0-9.]*")
_PS_SWITCHES = ("-noprofile", "-nologo", "-noninteractive", "-noexit", "-sta", "-mta", "-login", "-interactive")


def family(name: str) -> Family | None:
    if name in SHELLS:
        return FAMILIES["sh"]
    found = _FAMILY.fullmatch(name)
    return FAMILIES[found.group(1)] if found else None


def is_interpreter(name: str) -> bool:
    return name in ("deno", "bun", "pwsh", "powershell") or family(name) is not None


def resolve(cmd: Cmd) -> Cmd:
    """busybox runs its first argument as the tool: `busybox sh` is sh."""
    if cmd.name == "busybox" and cmd.args:
        return cmd._replace(name=cmd.args[0].lower(), args=cmd.args[1:])
    return cmd


def program(cmd: Cmd) -> tuple[str, str]:
    """How an interpreter gets its program: ('stdin'|'code'|'script'|'module', the code or script text)."""
    cmd = resolve(cmd)
    if cmd.name in ("pwsh", "powershell"):
        return _powershell(cmd.args)
    if cmd.name in ("deno", "bun"):
        return _runtime(cmd.args)
    fam, args, i = family(cmd.name) or FAMILIES["sh"], cmd.args, 0
    while i < len(args):
        arg, value = args[i], args[i + 1] if i + 1 < len(args) else ""
        kind = _flag_kind(fam, arg)
        if arg in STDIN_PATHS:
            return "stdin", arg
        if kind:
            return kind, value
        if arg == "--" or not arg.startswith(("-", "+")):
            script = value if arg == "--" else arg
            return ("script", script) if script else ("stdin", "")
        i += 2 if arg in fam.values else 1
    return "stdin", ""


def _runtime(args: list[str]) -> tuple[str, str]:
    """deno and bun: `run -` reads stdin, `eval`/`-e` takes code; anything else runs a file or a URL."""
    if "-" in args:
        return "stdin", "-"
    for i, arg in enumerate(args):
        if arg in ("eval", "-e", "--eval"):
            return "code", args[i + 1] if i + 1 < len(args) else ""
    return "", ""


def _flag_kind(fam: Family, arg: str) -> str:
    """'code' or 'module' when `arg` is the flag that names the program, 'stdin' for a shell's -s, else ''."""
    if arg in fam.code or _in_cluster(arg, fam.letters, fam.stops):
        return "code"
    if arg in fam.module:
        return "module"
    return "stdin" if fam is FAMILIES["sh"] and _in_cluster(arg, "s", fam.stops) else ""


def _in_cluster(arg: str, letters: str, stops: str) -> bool:
    """Whether a short-option cluster (-xec) carries one of `letters` before a letter that takes a value."""
    if not letters or arg[:1] != "-" or arg[1:2] == "-":
        return False
    for char in arg[1:]:
        if char in letters:
            return True
        if char in stops:
            return False
    return False


def _powershell(args: list[str]) -> tuple[str, str]:
    i = 0
    while i < len(args):
        low, value = args[i].lower(), args[i + 1] if i + 1 < len(args) else ""
        if abbreviates(low, "-file", 2):
            return ("stdin", value) if value == "-" else ("script", value)
        if abbreviates(low, "-command", 2) or abbreviates(low, "-encodedcommand", 2) or low == "-ec":
            return ("stdin", value) if value == "-" else ("code", value)
        if not low.startswith("-"):
            return "script", args[i]
        switch = low in ("-l", "-i") or any(abbreviates(low, full, 3) for full in _PS_SWITCHES)
        i += 1 if switch else 2
    return "stdin", ""
