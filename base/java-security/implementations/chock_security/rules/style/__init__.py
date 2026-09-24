"""The style pack: Code style."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="style",
    title="Code style",
    covers=(
        "The conventions Checkstyle and PMD enforce that a reviewer would otherwise repeat: imports, naming, console output in production code, statement shape."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = ()
