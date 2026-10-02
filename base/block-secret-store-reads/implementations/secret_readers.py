"""Which arguments of a reading or copying command are files it reads (stdlib only)."""

from __future__ import annotations

import re

from chock_shellparse import Cmd, flags_of, operands, positionals

PATTERN_VALUES = frozenset(
    (
        *("-e", "--regexp", "--expression", "-m", "--max-count", "-A", "-B", "-C", "--context", "-g", "--glob"),
        *("-t", "--type", "-T", "--type-not", "--include", "--exclude", "--exclude-dir", "-d", "-D"),
        *("--directories", "--devices"),
    )
)
PROGRAM_FLAGS = ("-e", "--regexp", "--expression")
OWN_PROGRAM = frozenset(("-e", "-f", "--regexp", "--file", "--expression", "--from-file"))
TARGET_FLAGS = frozenset(("-t", "--target-directory", "--suffix"))
TRANSPORT_VALUES = {
    "scp": frozenset(("-i", "-P", "-o", "-F", "-l", "-J", "-c", "-S")),
    "rsync": frozenset(("-e", "-M")),
}
FILE_VALUES = ("--file", "--from-file", "--input", "--in", "--files-from")
REMOTE = re.compile(r"^(?:[\w.-]+@)?[\w.-]{2,}:")


def values(args: list[str], flags: tuple[str, ...]) -> list[str]:
    """The values of `-e X`, `--expression X` and `--expression=X` style options."""
    found = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg in flags]
    return found + [arg.split("=", 1)[1] for arg in args if arg.startswith(tuple(f"{f}=" for f in flags))]


def program(cmd: Cmd) -> str:
    """The script text a sed or awk command runs: the first operand, or the `-e` values."""
    given = values(cmd.args, PROGRAM_FLAGS)
    if given or flags_of(cmd.args) & OWN_PROGRAM:
        return "\n".join(given)
    ops = positionals(cmd.args, PATTERN_VALUES)
    return ops[0] if ops else ""


def _files_of(cmd: Cmd) -> list[str]:
    ops = positionals(cmd.args, PATTERN_VALUES)
    return ops if flags_of(cmd.args) & OWN_PROGRAM else ops[1:]


def _sources(cmd: Cmd) -> list[str]:
    ops = positionals(cmd.args, TARGET_FLAGS | TRANSPORT_VALUES.get(cmd.name, frozenset()))
    named = bool(flags_of(cmd.args) & {"-t", "--target-directory"})
    sources = ops if named else ops[:-1] or ops
    return [op for op in sources if not REMOTE.match(op)] if cmd.name in TRANSPORT_VALUES else sources


def _archive(cmd: Cmd) -> list[str]:
    extracting = bool(flags_of(cmd.args) & {"-x", "--extract", "--get"})
    base = "" if extracting else next(iter(values(cmd.args, ("-C", "--directory"))), "")
    ops = positionals(cmd.args, frozenset(("-C", "--directory")))
    joined = [op if op.startswith(("/", "~", "$")) else f"{base}/{op}" for op in ops] if base else ops
    return [*joined, base] if base else joined


def candidates(cmd: Cmd, mode: str) -> list[str]:
    """Paths a command in `mode` reads, as written. Long `--file=X` style values count; pattern text does not."""
    given = [arg.split("=", 1)[1] for arg in cmd.args if arg.startswith(tuple(f"{f}=" for f in FILE_VALUES))]
    if mode in ("pattern-first", "program-first"):
        return [*_files_of(cmd), *given]
    handlers = {"sources": _sources, "archive": _archive}
    if mode == "dd":
        return [arg[3:] for arg in cmd.args if arg.startswith("if=")]
    return [*(handlers[mode](cmd) if mode in handlers else operands(cmd.args)), *given]
