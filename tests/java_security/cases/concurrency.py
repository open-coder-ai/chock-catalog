"""Cases for the concurrency pack: Concurrency.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

STATIC_DATE_FORMAT = "concurrency-static-date-format"
DOUBLE_CHECKED_LOCKING = "concurrency-double-checked-locking"
SYNC_ON_SHARED_LOCK = "concurrency-synchronization-on-shared-lock"
EMPTY_SYNC_BLOCK = "concurrency-empty-synchronized-block"
WAIT_NOT_IN_LOOP = "concurrency-wait-not-in-loop"
SLEEP_IN_SYNCHRONIZED = "concurrency-sleep-in-synchronized"
NOTIFY_NOT_NOTIFYALL = "concurrency-notify-instead-of-notifyall"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # concurrency-static-date-format
    (STATIC_DATE_FORMAT, "C.java", 'private static SimpleDateFormat FMT = new SimpleDateFormat("yyyy");\n', [1]),
    (
        STATIC_DATE_FORMAT,
        "C.java",
        'private static final SimpleDateFormat FMT = new SimpleDateFormat("yyyy");\n',
        [1],
    ),
    (STATIC_DATE_FORMAT, "C.java", "private static Calendar CAL;\n", [1]),
    (STATIC_DATE_FORMAT, "C.java", 'private SimpleDateFormat fmt = new SimpleDateFormat("yyyy");\n', []),
    (
        STATIC_DATE_FORMAT,
        "C.java",
        'void m() {\n  SimpleDateFormat fmt = new SimpleDateFormat("yyyy");\n}\n',
        [],
    ),
    (
        STATIC_DATE_FORMAT,
        "C.java",
        'private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy");\n',
        [],
    ),
    # concurrency-double-checked-locking
    (
        DOUBLE_CHECKED_LOCKING,
        "S.java",
        "class S {\n"
        "  private Helper helper;\n"
        "  Helper get() {\n"
        "    if (helper == null) {\n"
        "      synchronized (this) {\n"
        "        if (helper == null) {\n"
        "          helper = new Helper();\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "    return helper;\n"
        "  }\n"
        "}\n",
        [6],
    ),
    (
        DOUBLE_CHECKED_LOCKING,
        "S.java",
        "class S {\n"
        "  private volatile Helper helper;\n"
        "  Helper get() {\n"
        "    if (helper == null) {\n"
        "      synchronized (this) {\n"
        "        if (helper == null) {\n"
        "          helper = new Helper();\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "    return helper;\n"
        "  }\n"
        "}\n",
        [],
    ),
    (
        DOUBLE_CHECKED_LOCKING,
        "S.java",
        "class S {\n  Helper get() {\n    if (helper == null) {\n      helper = new Helper();\n    }\n    return helper;\n  }\n}\n",
        [],
    ),
    (
        DOUBLE_CHECKED_LOCKING,
        "S.java",
        "class S {\n"
        "  Helper get() {\n"
        "    if (helper == null) {\n"
        "      synchronized (this) {\n"
        "        if (other == null) {\n"
        "          other = new Helper();\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "    return helper;\n"
        "  }\n"
        "}\n",
        [],
    ),
    # concurrency-synchronization-on-shared-lock
    (SYNC_ON_SHARED_LOCK, "C.java", 'synchronized ("lock") {\n  x();\n}\n', [1]),
    (SYNC_ON_SHARED_LOCK, "C.java", "synchronized (new Object()) {\n  x();\n}\n", [1]),
    (SYNC_ON_SHARED_LOCK, "C.java", "synchronized (getClass()) {\n  x();\n}\n", [1]),
    (SYNC_ON_SHARED_LOCK, "C.java", "synchronized (Boolean.TRUE) {\n  x();\n}\n", [1]),
    (SYNC_ON_SHARED_LOCK, "C.java", "synchronized (this) {\n  x();\n}\n", []),
    (SYNC_ON_SHARED_LOCK, "C.java", "synchronized (lockField) {\n  x();\n}\n", []),
    (SYNC_ON_SHARED_LOCK, "C.java", "synchronized (SomeClass.class) {\n  x();\n}\n", []),
    # concurrency-empty-synchronized-block
    (EMPTY_SYNC_BLOCK, "C.java", "synchronized (lock) {\n}\n", [1]),
    (EMPTY_SYNC_BLOCK, "C.java", "synchronized (lock) {\n  // nothing yet\n}\n", [1]),
    (EMPTY_SYNC_BLOCK, "C.java", "synchronized (lock) {\n  doWork();\n}\n", []),
    (EMPTY_SYNC_BLOCK, "C.java", "synchronized void m() {\n  doWork();\n}\n", []),
    (EMPTY_SYNC_BLOCK, "C.java", "synchronized (lock) {\n  doWork();\n", []),
    # concurrency-wait-not-in-loop
    (
        WAIT_NOT_IN_LOOP,
        "C.java",
        "void m() {\n  synchronized (this) {\n    wait();\n  }\n}\n",
        [3],
    ),
    (
        WAIT_NOT_IN_LOOP,
        "C.java",
        "}\nvoid m() {\n  synchronized (this) {\n    wait();\n  }\n}\n",
        [4],
    ),
    (
        WAIT_NOT_IN_LOOP,
        "C.java",
        "void m() {\n  if (x) {\n  }\n  synchronized (this) {\n    wait();\n  }\n}\n",
        [5],
    ),
    (
        WAIT_NOT_IN_LOOP,
        "C.java",
        "void m() {\n  synchronized (this) {\n    while (!ready) {\n      wait();\n    }\n  }\n}\n",
        [],
    ),
    (
        WAIT_NOT_IN_LOOP,
        "C.java",
        "void m() {\n  synchronized (this) {\n    for (int i = 0; i < 1 && !ready; i++) {\n      wait();\n    }\n  }\n}\n",
        [],
    ),
    # concurrency-sleep-in-synchronized
    (
        SLEEP_IN_SYNCHRONIZED,
        "C.java",
        "void m() {\n  synchronized (this) {\n    Thread.sleep(100);\n  }\n}\n",
        [3],
    ),
    (SLEEP_IN_SYNCHRONIZED, "C.java", "void m() {\n  Thread.sleep(100);\n}\n", []),
    (
        SLEEP_IN_SYNCHRONIZED,
        "C.java",
        "void m() {\n  while (retry) {\n    Thread.sleep(100);\n  }\n}\n",
        [],
    ),
    # concurrency-notify-instead-of-notifyall
    (NOTIFY_NOT_NOTIFYALL, "C.java", "void m() {\n  notify();\n}\n", [2]),
    (NOTIFY_NOT_NOTIFYALL, "C.java", "void m() {\n  this.notify();\n}\n", [2]),
    (NOTIFY_NOT_NOTIFYALL, "C.java", "void m() {\n  notifyAll();\n}\n", []),
    (NOTIFY_NOT_NOTIFYALL, "C.java", "void m() {\n  lock.notify();\n}\n", []),
]
