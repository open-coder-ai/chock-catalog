"""Which arguments of a reading or copying command are files it reads, and what an interpreter runs (stdlib only)."""

from __future__ import annotations

import re
from typing import NamedTuple

from chock_shellparse import Cmd, flags_of, operands, positionals

# Per-tool options whose next word is a value, and the options that bring their own pattern or program.
_GREP = frozenset(("-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context", "-d", "-D", "--include"))
_GREP |= frozenset(("--exclude", "--exclude-dir", "--label", "--directories", "--devices"))
_RG = frozenset(("-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "-g", "--glob", "-t", "--type", "-T"))
_RG |= frozenset(("--type-not", "--context", "-M", "-j", "-E", "--encoding"))
_AG = frozenset(("-A", "-B", "-C", "-G", "-g", "-m", "-p", "--depth", "--ignore", "--file-search-regex"))
_SED = frozenset(("-e", "--expression", "-l", "--line-length", "-s"))
_NONE: frozenset[str] = frozenset()
VALUES = {
    **dict.fromkeys(("grep", "egrep", "fgrep"), _GREP),
    "rg": _RG,
    "ag": _AG,
    "ack": _AG,
    **dict.fromkeys(("sed", "awk", "gawk", "mawk"), _SED),
}
OWN = {
    **dict.fromkeys(("grep", "egrep", "fgrep", "rg"), frozenset(("-e", "-f", "--regexp", "--file"))),
    **dict.fromkeys(("sed", "awk", "gawk", "mawk"), frozenset(("-e", "-f", "--expression", "--file"))),
}
PROGRAM_FLAGS = ("-e", "--regexp", "--expression")
TARGET_FLAGS = frozenset(("-t", "--target-directory", "--suffix"))
TRANSPORT_VALUES = {
    "scp": frozenset(("-i", "-P", "-o", "-F", "-l", "-J", "-c", "-S")),
    "rsync": frozenset(("-e", "-M")),
}
FILE_VALUES = ("--file", "--from-file", "--input", "--in", "--files-from", "--post-file", "--body-file")
REMOTE = re.compile(r"^(?:[\w.-]+@)?[\w.-]{2,}:")
WRAPPED = re.compile(r"^(?:[\w-]+=)?@|^file://")
ATTACHED = re.compile(r"^(?:-[A-Za-z]|--[\w-]+=)?(?:[\w-]+=)?(?:[\w-]+@|[@<])?(?:file://)?")
FETCHERS = {
    "curl": frozenset(("-o", "--output")),
    "wget": frozenset(("-O", "-o", "-P", "--output-document", "--output-file", "--directory-prefix")),
}


class Interp(NamedTuple):
    """How one interpreter names its program: options whose value is code, a module, or something else."""

    code: frozenset[str]
    module: frozenset[str] = frozenset()
    values: frozenset[str] = frozenset()


def _i(code: str, module: str = "", values: str = "") -> Interp:
    return Interp(frozenset(code.split()), frozenset(module.split()), frozenset(values.split()))


#: A short option is read inside a cluster too (`perl -ne 'code'`, `python -Wd -c code`); a value may be attached.
INTERPRETERS = {
    "python": _i("-c", "-m", "-W -X --check-hash-based-pycs"),
    "node": _i("-e --eval -p --print", "", "-r --require --import --loader --input-type -C --conditions"),
    "ruby": _i("-e", "", "-I -r -C -E -F"),
    "perl": _i("-e -E", "", "-I -M -m -F"),
    "php": _i("-r -f", "", "-c -d -z"),
    "lua": _i("-e", "", "-l"),
    "deno": _i("eval", "", "-c --config --import-map --lock"),
    "bun": _i("-e --eval -p --print", "", "-r --preload"),
}
_ALIASES = {"nodejs": "node"}


def values(args: list[str], flags: tuple[str, ...]) -> list[str]:
    """The values of `-e X`, `--expression X` and `--expression=X` style options."""
    found = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg in flags]
    return found + [arg.split("=", 1)[1] for arg in args if arg.startswith(tuple(f"{f}=" for f in flags))]


def _own(cmd: Cmd) -> bool:
    return bool(flags_of(cmd.args) & OWN.get(cmd.name, frozenset(("-f", "--from-file"))))


def program(cmd: Cmd) -> str:
    """The script text a sed or awk command runs: the first operand, or the `-e` values."""
    given = values(cmd.args, PROGRAM_FLAGS)
    if given or _own(cmd):
        return "\n".join(given)
    ops = positionals(cmd.args, VALUES.get(cmd.name, _NONE))
    return ops[0] if ops else ""


def _files_of(cmd: Cmd) -> list[str]:
    ops = positionals(cmd.args, VALUES.get(cmd.name, _NONE))
    return ops if _own(cmd) else ops[1:]


def _sources(cmd: Cmd) -> list[str]:
    ops = positionals(cmd.args, TARGET_FLAGS | TRANSPORT_VALUES.get(cmd.name, frozenset()))
    named = bool(flags_of(cmd.args) & {"-t", "--target-directory"})
    sources = ops if named else ops[:-1] or ops
    return [op for op in sources if not REMOTE.match(op)] if cmd.name in TRANSPORT_VALUES else sources


def _archive(cmd: Cmd) -> list[str]:
    extracting = bool(flags_of(cmd.args) & {"-x", "--extract", "--get"})
    base = "" if extracting else next(iter(values(cmd.args, ("-C", "--directory"))), "")
    ops = positionals(cmd.args, frozenset(("-C", "--directory")))
    return [op if op.startswith(("/", "~", "$")) else f"{base}/{op}" for op in ops] if base else ops


def _fetch_inputs(cmd: Cmd) -> list[str]:
    """What curl and wget read from disk: attached `@file` values, not output files or URLs."""
    outputs, found, skip = FETCHERS[cmd.name], [], False
    for arg in cmd.args:
        url = "://" in arg and not arg.startswith("file://")
        if not skip and arg not in outputs and arg.split("=", 1)[0] not in outputs and not url:
            found.append(ATTACHED.sub("", arg))
        skip = not skip and arg in outputs
    return found


def candidates(cmd: Cmd, mode: str) -> list[str]:
    """Paths a command in `mode` reads, as written. Long `--file=X` style values count; pattern text does not."""
    given = [arg.split("=", 1)[1] for arg in cmd.args if arg.startswith(tuple(f"{f}=" for f in FILE_VALUES))]
    if mode in ("pattern-first", "program-first"):
        return [*_files_of(cmd), *given]
    if mode == "dd":
        return [arg[3:] for arg in cmd.args if arg.startswith("if=")]
    if cmd.name in FETCHERS:
        return _fetch_inputs(cmd) + given
    handlers = {"sources": _sources, "archive": _archive}
    return [WRAPPED.sub("", p) for p in (handlers[mode](cmd) if mode in handlers else operands(cmd.args)) + given]


def _cluster(arg: str, nxt: str, spec: Interp) -> tuple[str, str | None, int]:
    """('code'|'module'|'', its text, words taken) for a short-option cluster; a value is the rest of the cluster, else the next word."""
    for at, char in enumerate(arg[1:], 1):
        rest = arg[at + 1 :]
        if f"-{char}" in spec.code:
            return "code", rest or nxt, 1 if rest else 2
        if f"-{char}" in spec.module:
            return "module", "", 2
        if f"-{char}" in spec.values:
            return "", None, 1 if rest else 2
    return "", None, 1


def program_text(cmd: Cmd) -> str:
    """The text an interpreter runs: its -c/-e code or the script operand it names; later words are the program's own arguments."""
    name = cmd.name.rstrip("0123456789.")
    spec = INTERPRETERS.get(_ALIASES.get(name, name), Interp(frozenset()))
    args = cmd.args[1:] if name in ("deno", "bun") and cmd.args[:1] == ["run"] else cmd.args
    i = 0
    while i < len(args):
        arg, nxt = args[i], args[i + 1] if i + 1 < len(args) else ""
        if arg in spec.code or arg == "--":
            return nxt
        if arg in spec.module or arg == "-":
            return ""
        if arg.split("=", 1)[0] in spec.code and "=" in arg:
            return arg.split("=", 1)[1]
        if not arg.startswith("-"):
            return arg
        if arg in spec.values:
            i += 2
            continue
        kind, text, taken = _cluster(arg, nxt, spec) if arg[1:2] != "-" else ("", None, 1)
        if kind:
            return text or ""
        i += taken
    return ""
