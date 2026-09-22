"""What a technology pack contributes: its rules, and the vendor facts they read."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from chock_security.decision import FileText, Finding

_DATA = Path(__file__).resolve().parent / "data"


def facts(pack: str) -> dict:
    """The vendor facts a pack's rules read. Tokens and API names live here, decisions do not."""
    return json.loads((_DATA / f"{pack}.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Rule:
    """One refusable construct: the files it reads, and the scan that finds it."""

    id: str
    pack: str
    title: str
    suffixes: tuple[str, ...]
    scan: Callable[[FileText], Iterator[Finding]]
    #: One negative constraint, in the compressed form an agent reads as an ambient rule.
    #: Rendered, never hand-written twice -- a rule and its prose cannot drift apart.
    constraint: str = ""
    #: What this rule refuses, and what it stays silent on -- the setup page's own two texts.
    #: Rendered into the README table and the setup contract; never hand-written twice.
    refuses: str = ""
    silent_on: str = ""

    def reads(self, text: FileText) -> bool:
        return text.suffix in self.suffixes
