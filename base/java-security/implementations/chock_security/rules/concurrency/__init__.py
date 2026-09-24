"""The concurrency pack: Concurrency."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="concurrency",
    title="Concurrency",
    covers=(
        "Threads, locks, executors and shared state: unsafe publication, broken double-checked locking, locks on shared or boxed objects, thread-unsafe formatters held in static fields, deprecated thread control."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = ()
