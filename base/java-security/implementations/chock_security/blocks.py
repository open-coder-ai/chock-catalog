"""The blocks a method's lines have opened, and the clears that end with them.

A check that clears a variable clears it to the end of the block it sits in, so a guard in a lambda, a
`try`, an `if` or a loop protects what follows it there and nothing after the block closes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_SWITCH = re.compile(r"(?<![\w$])switch\s*\([^;{}]*\)\s*$")


@dataclass(eq=False)
class Frame:
    """An open block, and what to carry again when it closes."""

    switch: bool
    restore: set[str] = field(default_factory=set)


@dataclass
class _Delay:
    names: set[str]
    base: int
    host: Frame | None


class Frames:
    """The blocks a method's lines have opened and not yet closed, and the clears that end with them."""

    def __init__(self) -> None:
        self.stack: list[Frame] = []
        self._segment = ""
        self._delays: list[_Delay] = []

    @property
    def in_switch(self) -> bool:
        return any(frame.switch for frame in self.stack)

    def _feed(self, code: str) -> list[Frame]:
        closed: list[Frame] = []
        for char in code:
            if char == "{":
                self.stack.append(Frame(_SWITCH.search(self._segment) is not None))
            elif char == "}" and self.stack:
                closed.append(self.stack.pop())
            self._segment = "" if char in "{};}" else self._segment + char
        return closed

    def _clear(self, names: set[str] | frozenset[str], host: Frame | None, tainted: set[str]) -> None:
        if host in self.stack:
            host.restore |= names & tainted
        tainted -= names

    def settle(
        self, code: str, tainted: set[str], cleared: frozenset[str], delayed: frozenset[str], scoped: frozenset[str]
    ) -> None:
        """Take one line of code and what its checks decided (cleared now, once the exiting body ends, or until the block it opens closes): a name cleared stays cleared to the end
        of the block the check sits in, and a block's clears are undone when it closes."""
        host, base = (self.stack[-1] if self.stack else None), len(self.stack)
        for frame in self._feed(code):
            tainted |= frame.restore
        for delay in [d for d in self._delays if len(self.stack) <= d.base]:
            self._delays.remove(delay)
            self._clear(delay.names, delay.host, tainted)
        self._clear(cleared, host, tainted)
        if delayed:
            self._delays.append(_Delay(set(delayed), base, host))
        if scoped and len(self.stack) > base:
            self._clear(scoped, self.stack[-1], tainted)
