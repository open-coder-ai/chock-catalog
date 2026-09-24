"""The performance pack: Performance."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="performance",
    title="Performance",
    covers=(
        "Allocation and complexity mistakes a profiler would find later: boxing constructors, strings built in loops, patterns recompiled per call, the wrong collection access for the job."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = ()
