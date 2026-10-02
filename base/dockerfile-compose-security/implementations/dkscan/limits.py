"""What the shell rules can read in full; past it an instruction is reported as too large to judge, never passed.

The patterns in shellrules bound every repeat so a crafted line costs linear time. A command that
runs past those bounds (a segment longer than SEGMENT, more than PREFIXES wrappers or assignments
before the command, a prefix word longer than WORD) would otherwise hide what follows, so it is a
finding of its own. An instruction longer than TEXT is reported the same way and not scanned.
"""

from __future__ import annotations

import re

TEXT = 64 * 1024
SEGMENT = 4096
PREFIXES = 32
WORD = 128
SEGMENTS = re.compile(r"[^;&|\n]+")
ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=")
KEYWORDS = frozenset({"RUN", "ONBUILD"})
WRAPPERS = frozenset({"sudo", "doas", "env", "exec", "command", "nohup", "nice", "time", "stdbuf", "xargs", "timeout"})


def _prefix(words: list[str]) -> tuple[int, int]:
    """(count, longest) of the wrapper, flag and assignment words before a segment's command."""
    count = longest = 0
    after_wrapper = False
    while words and (words[0].upper() in KEYWORDS or (words[0].startswith("--") and count == 0)):
        words = words[1:]
    for word in words:
        wrapper = word in WRAPPERS
        if not (wrapper or ASSIGNMENT.match(word) or (after_wrapper and word.startswith("-"))):
            break
        after_wrapper = wrapper or after_wrapper
        count += 1
        longest = max(longest, len(word))
    return count, longest


def unjudgeable(text: str) -> str:
    """Why `text` is past what the shell rules read in full, or ""."""
    if len(text) > TEXT:
        return f"the instruction is longer than {TEXT // 1024} KiB"
    for segment in SEGMENTS.finditer(text):
        if segment.end() - segment.start() > SEGMENT:
            return f"a command is longer than {SEGMENT} characters"
        count, longest = _prefix(segment.group().split())
        if count > PREFIXES or longest > WORD:
            return f"a command has more than {PREFIXES} wrappers or assignments, or one longer than {WORD} characters"
    return ""
