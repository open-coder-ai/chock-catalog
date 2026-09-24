"""The performance pack: Performance."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.performance.performance_boxing_constructor import RULE as BOXING_CONSTRUCTOR
from chock_security.rules.performance.performance_legacy_collection import RULE as LEGACY_COLLECTION
from chock_security.rules.performance.performance_map_keyset_get import RULE as MAP_KEYSET_GET
from chock_security.rules.performance.performance_size_check import RULE as SIZE_CHECK
from chock_security.rules.performance.performance_string_concat_loop import RULE as STRING_CONCAT_LOOP

PACK = Pack(
    id="performance",
    title="Performance",
    covers=(
        "Allocation and complexity mistakes a profiler would find later: boxing constructors, strings built in loops, the wrong Map iterator, size() checks that should be isEmpty(), and synchronized legacy collections."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = (
    BOXING_CONSTRUCTOR,
    STRING_CONCAT_LOOP,
    MAP_KEYSET_GET,
    SIZE_CHECK,
    LEGACY_COLLECTION,
)
