"""Every rule's cases: text it must refuse, and the correct form it must stay silent on."""

from __future__ import annotations

from typing import NamedTuple


class Case(NamedTuple):
    """One file: which rule it is about, where it lives, what it says, and what it does in words. `head` is the file as last committed."""

    rule: str
    path: str
    text: str
    note: str
    head: str | None = None
