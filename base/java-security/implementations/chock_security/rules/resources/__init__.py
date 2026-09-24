"""The resources pack: Resources and lifecycle."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="resources",
    title="Resources and lifecycle",
    covers=(
        "Streams, readers, connections, statements, sockets and executors that must be closed; finalizers, forced garbage collection and exiting the JVM from library code."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = ()
