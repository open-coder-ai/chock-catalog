"""What a rule reports, and the file text it reads to report it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

#: What a rule does when it fires. agentseam spells ASK 'escalate' and accepts 'ask' for it.
ALLOW = "allow"
DENY = "deny"
ASK = "ask"

#: Ordered by how much they stop: a pack holding both reports the strongest.
VERDICTS = (ALLOW, ASK, DENY)

#: What every door says when it cannot reach a decision. A guard that fails must refuse:
#: an allow it never judged is indistinguishable from an allow it judged and meant.
UNJUDGED = (
    "chock-security could not reach a decision ({reason}). Refusing the action rather than "
    "allowing one it never judged."
)


@dataclass(frozen=True)
class Finding:
    """One refused construct: which rule refused it, where, and what to do instead."""

    rule_id: str
    path: str
    line_no: int
    line: str
    message: str
    verdict: str = DENY

    def render(self) -> str:
        """One line a human reads in a hook's output. The matched line is never echoed."""
        return f"{self.path}:{self.line_no}: [{self.verdict}: {self.rule_id}] {self.message}"


@dataclass(frozen=True)
class FileText:
    """A revision of one file, as a rule sees it: the whole text, not a diff hunk."""

    path: str
    text: str

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.path).suffix.lower()

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def holds(self, *needles: str) -> bool:
        """Whether any needle appears anywhere in the file, for a file-level context test."""
        return any(n in self.text for n in needles)
