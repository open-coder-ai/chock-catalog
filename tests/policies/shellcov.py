"""Line coverage for the bash guards, from bash's own execution trace.

kcov is not packaged for the CI image and bashcov needs a Ruby toolchain, so this reads what
bash itself reports: `BASH_ENV` points every bash the guards run in at a preamble that turns on
xtrace with `PS4` carrying the source file and line number, and the trace goes to a file.

The unit is the statement, not the physical line. Bash reports a command continued over several
lines at its first or its last line (an array literal at its closing parenthesis, a pipeline
split after `|` at the last), so the lines of one statement are grouped and the statement counts
as run when bash reported any of them. Lines that are syntax and never a command -- `then`,
`fi`, `done`, `;;`, braces, a function header, a case pattern with nothing after it, comments,
blank lines and heredoc bodies -- are not statements.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_SEP = "\x1f"
PREAMBLE = """exec {__cov_fd}>>"$CHOCK_SHELLCOV_TRACE"
BASH_XTRACEFD=$__cov_fd
PS4=$'+\\x1f${BASH_SOURCE[0]:-}\\x1f${LINENO}\\x1f'
set -x
"""

#: Syntax a statement may consist of alone without being a command.
_SYNTAX = re.compile(r"^(then|else|fi|do|esac|;;|\{|\}|\)|in|fi;;|done;;|\};?)$|^done\b")
_FUNCTION = re.compile(r"^(function\s+)?[\w:.-]+\s*\(\)\s*\{?$|^function\s+[\w:.-]+\s*\{?$")
#: A case arm's pattern alone on its line: words, globs and `|`, closed by `)`.
#: An arm with no command (`pat) ;;`) runs nothing bash could report, so it is syntax too.
_PATTERN = re.compile(r"^\(?[^()$`;]*\)(\s*;;)?$")
_CONTINUES = re.compile(r"(\\|\||&&|\|\||\()$")
#: `<<WORD`, `<<-'WORD'`; never the here-string `<<<`.
_HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*(['\"]?)([A-Za-z_][\w]*)\1")


def _code(line: str, quote: str) -> tuple[str, str, int]:
    """(line without its comment, quote still open at its end, paren depth change)."""
    out, depth, i = [], 0, 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                out.append(line[i : i + 2])
                i += 2
                continue
            quote = "" if ch == quote else quote
        elif ch == "#" and (i == 0 or line[i - 1] in " \t;"):
            break
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            out.append(line[i : i + 2])
            i += 2
            continue
        else:
            depth += {"(": 1, ")": -1}.get(ch, 0)
        out.append(ch)
        i += 1
    return "".join(out).rstrip(), quote, depth


def statements(script: str) -> list[tuple[int, ...]]:
    """Every statement in the script, as the 1-based line numbers it spans."""
    found: list[tuple[int, ...]] = []
    group: list[int] = []
    text: list[str] = []
    quote, depth, heredoc = "", 0, ""
    for number, raw in enumerate(script.splitlines(), 1):
        if heredoc:
            group.append(number)
            if raw.strip() == heredoc:
                heredoc = ""
            else:
                continue
        else:
            line, quote, change = _code(raw, quote)
            depth = max(0, depth + change)
            if line.strip():
                group.append(number)
                text.append(line.strip())
            opened = _HEREDOC.search(line)
            if opened:
                heredoc = opened.group(2)
                continue
            if quote or depth or _CONTINUES.search(line) and not _SYNTAX.match(line.strip()):
                continue
        if group:
            joined = " ".join(text)
            if not (_SYNTAX.match(joined) or _FUNCTION.match(joined) or _PATTERN.match(joined)):
                found.append(tuple(group))
            group, text = [], []
    return found


def reported(trace: Path, script: Path) -> set[int]:
    """The line numbers bash reported running in `script`."""
    lines: set[int] = set()
    if not trace.is_file():
        return lines
    target = str(script.resolve())
    for record in trace.read_text(encoding="utf-8", errors="replace").split("+" + _SEP)[1:]:
        source, _, rest = record.partition(_SEP)
        number = rest.partition(_SEP)[0]
        if source and number.isdigit() and str(Path(source).resolve()) == target:
            lines.add(int(number))
    return lines


def uncovered(script: Path, trace: Path) -> list[tuple[int, ...]]:
    """Statements in `script` bash never reported running."""
    ran = reported(trace, script)
    return [s for s in statements(script.read_text(encoding="utf-8")) if not ran.intersection(s)]


@contextmanager
def tracing(directory: Path) -> Iterator[Path]:
    """Trace every bash started inside the block; yields the trace file."""
    preamble = directory / "shellcov-preamble.sh"
    preamble.write_text(PREAMBLE, encoding="utf-8")
    trace = directory / "shellcov-trace.txt"
    saved = {k: os.environ.get(k) for k in ("BASH_ENV", "CHOCK_SHELLCOV_TRACE")}
    os.environ["BASH_ENV"] = str(preamble)
    os.environ["CHOCK_SHELLCOV_TRACE"] = str(trace)
    try:
        yield trace
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
