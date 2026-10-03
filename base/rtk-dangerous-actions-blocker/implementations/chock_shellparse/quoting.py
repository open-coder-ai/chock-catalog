"""Split a segment of a command line into words when its quotes may not balance (stdlib only; shared byte for byte by the guards)."""

import re
import shlex
from functools import lru_cache

# One piece of a segment as the shell reads quoting: plain text, an escaped character, a quoted string.
_UNIT = re.compile(r"[^'\"\\]+|\\.|'[^']*+'|\"(?:[^\"\\]|\\.)*+\"", re.DOTALL)


def balance(part: str) -> tuple[bool, int | None]:
    """Whether the quotes of a segment balance, or else the last quote that opens at a balanced point (one left-to-right scan)."""
    at, last = 0, None
    while at < len(part):
        unit = _UNIT.match(part, at)
        if unit is None:  # a quote that is never closed, or a lone `\` ending the text
            return False, last if part[at] == "\\" else at
        if part[at] in "'\"":
            last = at
        at = unit.end()
    return True, None


@lru_cache(maxsize=128)  # a guard reads the same segment through several views of the line
def split_words(part: str) -> tuple[str, ...]:
    """Split one segment like a shell; a quote that is never closed makes the rest of the segment one word."""
    balanced, at = balance(part)
    if balanced:
        return tuple(shlex.split(part))
    if at is None:
        return tuple(part.split())
    return (*shlex.split(part[:at]), part[at + 1 :])
