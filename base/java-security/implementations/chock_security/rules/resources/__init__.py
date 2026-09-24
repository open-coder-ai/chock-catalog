"""The resources pack: Resources and lifecycle."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.resources.resources_finalize_override import RULE as FINALIZE_OVERRIDE
from chock_security.rules.resources.resources_forced_gc import RULE as FORCED_GC
from chock_security.rules.resources.resources_run_finalizers_on_exit import RULE as RUN_FINALIZERS_ON_EXIT
from chock_security.rules.resources.resources_system_exit import RULE as SYSTEM_EXIT
from chock_security.rules.resources.resources_unclosed_closeable import RULE as UNCLOSED_CLOSEABLE

PACK = Pack(
    id="resources",
    title="Resources and lifecycle",
    covers=(
        "Streams, readers, connections, statements, sockets and executors that must be closed; finalizers, forced garbage collection and exiting the JVM from library code."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = (
    UNCLOSED_CLOSEABLE,
    FINALIZE_OVERRIDE,
    FORCED_GC,
    SYSTEM_EXIT,
    RUN_FINALIZERS_ON_EXIT,
)
