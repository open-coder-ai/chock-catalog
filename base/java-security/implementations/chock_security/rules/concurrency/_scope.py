"""Which control-flow block a line sits inside, by brace depth -- enough to tell whether a
wait()/sleep() call is inside a loop or a synchronized block without a full parser."""

from __future__ import annotations

import re

_KEYWORD = re.compile(r"^(?:\}\s*)?(while|for|synchronized|if|else|try|catch|do|switch)\b")


def _kind(line: str) -> str:
    """The control-flow keyword that opens this line's block, or "block" for anything else."""
    match = _KEYWORD.match(line.strip())
    return match.group(1) if match else "block"


def enclosing_kinds(lines: list[str], line_no: int) -> list[str]:
    """The stack of block kinds enclosing `lines[line_no - 1]`, outermost first.

    Conservative: a brace opened and closed on the same line as a later `{` is still counted
    correctly (depth tracks every character), and a kind is only as precise as the leading
    keyword on the line that opened it -- good enough to tell "inside a while/for loop" or
    "inside a synchronized block" from "not", never used for anything finer than that.
    """
    stack: list[str] = []
    for current in lines[: line_no - 1]:
        kind = _kind(current)
        for ch in current:
            if ch == "{":
                stack.append(kind)
            elif ch == "}" and stack:
                stack.pop()
    return stack
