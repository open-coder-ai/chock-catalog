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


def weaknesses() -> dict[str, dict[str, str]]:
    """The CWE entries rules cite, as MITRE's catalog names them, keyed by id."""
    return facts("cwe")["weaknesses"]


@dataclass(frozen=True)
class Pack:
    """A category of rules an adopter can switch as one: a framework, a layer, a platform."""

    id: str
    title: str
    #: What code this pack reads, in the words a developer would recognise their stack by.
    covers: str


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
    #: The weakness this construct is an instance of, as MITRE's CWE ids ("CWE-89"). Each must be
    #: in data/cwe.json and mappable there: a CWE that MITRE marks prohibited or discouraged for
    #: vulnerability mapping is a category, not evidence. Printed on every refusal.
    cwe: tuple[str, ...] = ()
    #: Where the construct is shown to be a vulnerability: the CVE, the vendor's own security
    #: documentation, the OWASP cheat sheet. A rule nobody outside this repository has called a
    #: vulnerability is an opinion, and a refused commit needs more than one.
    references: tuple[str, ...] = ()

    def reads(self, text: FileText) -> bool:
        return text.suffix in self.suffixes
