"""Judge only what a change adds: a finding stays when a line it involves is new against the baseline.

A finding involves its own line, the lines the analyser recorded for it (a flow's method header and the
assignments that carried the value to the sink), and the Java statement each of those sits in. A line is
new when the baseline holds fewer copies of it than the written text does.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from chock_security.decision import FileText, Finding
from chock_security.source import code

#: Where the runner sends the agent's writes, before they land and at the turn's end.
TOOL_USE = "tool_use"

Head = Callable[[str], "str | None"]

_ENDS = (";", "{", "}")
#: A statement longer than this is not read as one: the finding's own line stands for it.
_SPAN_LIMIT = 40


def on_disk(root: Path, path: str) -> str | None:
    """The file as it is on disk, or None when it is not there."""
    try:
        return (root / path).read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None


def baseline(root: Path, path: str, after: str, event: str | None, head: Head) -> str | None:
    """What the write replaces; None for a file with no earlier text, so every line of it is new.

    At commit that is HEAD. As the agent writes it is the file on disk; at the turn's end the disk
    already holds `after`, so it is HEAD again.
    """
    if event == TOOL_USE:
        disk = on_disk(root, path)
        if disk is not None and disk != after:
            return disk
    return head(path)


def _key(line: str) -> str:
    """A line as compared: without its indentation or a trailing comma, which appending an entry adds."""
    return line.strip().rstrip(",")


def new_lines(lines: list[str], before: str | None) -> set[int]:
    """1-based numbers of the lines beyond the baseline's copies (indentation, trailing comma ignored)."""
    if before is None:
        return set(range(1, len(lines) + 1))
    left = Counter(_key(line) for line in before.splitlines())
    fresh: set[int] = set()
    for number, line in enumerate(lines, 1):
        key = _key(line)
        if left[key] > 0:
            left[key] -= 1
        else:
            fresh.add(number)
    return fresh


def statement(text: FileText, line_no: int) -> range:
    """The lines of the Java statement `line_no` sits in; the line alone for anything else."""
    alone = range(line_no, line_no + 1)
    rows = code(text) if text.suffix == ".java" else []
    if not 0 < line_no <= len(rows):
        return alone

    def closed(index: int) -> bool:
        return not rows[index].strip() or rows[index].rstrip().endswith(_ENDS)

    first = line_no - 1
    while first > 0 and not closed(first - 1):
        first -= 1
    last = line_no - 1
    while last < len(rows) - 1 and not closed(last) and rows[last + 1].strip():
        last += 1
    span = range(first + 1, last + 2)
    return span if len(span) <= _SPAN_LIMIT else alone


def involved(finding: Finding, text: FileText) -> set[int]:
    """Every line a finding depends on."""
    lines: set[int] = set()
    for number in (finding.line_no, *finding.related):
        lines.update(statement(text, number))
    return lines


def only_new(findings: Iterable[Finding], files: Iterable[FileText], before: Mapping[str, str | None]) -> list[Finding]:
    """The findings with a new line among the lines they involve."""
    texts = {file.path: file for file in files}
    fresh = {path: new_lines(file.lines, before.get(path)) for path, file in texts.items()}
    return [f for f in findings if fresh[f.path] & involved(f, texts[f.path])]
