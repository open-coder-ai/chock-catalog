"""The concurrency pack: Concurrency."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.concurrency.concurrency_double_checked_locking import RULE as DOUBLE_CHECKED_LOCKING
from chock_security.rules.concurrency.concurrency_empty_synchronized_block import RULE as EMPTY_SYNCHRONIZED_BLOCK
from chock_security.rules.concurrency.concurrency_notify_instead_of_notifyall import RULE as NOTIFY_INSTEAD_OF_NOTIFYALL
from chock_security.rules.concurrency.concurrency_sleep_in_synchronized import RULE as SLEEP_IN_SYNCHRONIZED
from chock_security.rules.concurrency.concurrency_static_date_format import RULE as STATIC_DATE_FORMAT
from chock_security.rules.concurrency.concurrency_synchronization_on_shared_lock import (
    RULE as SYNCHRONIZATION_ON_SHARED_LOCK,
)
from chock_security.rules.concurrency.concurrency_wait_not_in_loop import RULE as WAIT_NOT_IN_LOOP

PACK = Pack(
    id="concurrency",
    title="Concurrency",
    covers=(
        "Threads, locks and shared state: unsafe publication, broken double-checked locking, locks on shared or boxed objects, thread-unsafe formatters held in static fields, and the wait()/notify()/sleep() misuses that break under real contention."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = (
    STATIC_DATE_FORMAT,
    DOUBLE_CHECKED_LOCKING,
    SYNCHRONIZATION_ON_SHARED_LOCK,
    EMPTY_SYNCHRONIZED_BLOCK,
    WAIT_NOT_IN_LOOP,
    SLEEP_IN_SYNCHRONIZED,
    NOTIFY_INSTEAD_OF_NOTIFYALL,
)
