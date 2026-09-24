"""A world-readable or world-writable file or preferences store is reachable by any app on device."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "android-world-accessible-file"

_FACTS = facts("android")["world_accessible"]

_MODE_MESSAGE = (
    "{token} makes this file or preferences store readable or writable by any app installed on "
    "the device, no permission required -- both constants were removed from the SDK for exactly "
    "this reason and now throw on modern targets. Use MODE_PRIVATE, and share data through a "
    f"content provider or an explicit Intent instead. A file meant to be public needs 'chock: "
    f"allow {RULE_ID}' on this line."
)

_PERMISSION_MESSAGE = (
    "This sets the file's permission bits to everyone, not just its owner, so any other app can "
    "read or write it directly off disk. Pass true for the second argument (owner-only), or drop "
    f"the two-argument call and rely on the private mode a file is created with. A file meant to "
    f"be shared this way needs 'chock: allow {RULE_ID}' on this line and a narrower mechanism "
    "considered first."
)

_SET_PERMISSIVE = re.compile(r"\.(setReadable|setWritable)\(\s*true\s*,\s*false\s*\)")


def scan(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(text.lines, 1):
        for token in _FACTS["mode_tokens"]:
            if token in line:
                yield Finding(RULE_ID, text.path, line_no, line, _MODE_MESSAGE.format(token=token))
                break
        else:
            if _SET_PERMISSIVE.search(line):
                yield Finding(RULE_ID, text.path, line_no, line, _PERMISSION_MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="World-readable or world-writable file",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(open): Context.MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE; "
        "never(chmod): file.setReadable(true, false)|setWritable(true, false) -- use MODE_PRIVATE"
    ),
    refuses="`MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE`; `setReadable`/`setWritable(true, false)`",
    silent_on="`MODE_PRIVATE`; `setReadable(true, true)`/`setReadable(true)` (owner-only)",
    cwe=("CWE-732", "CWE-276"),
    references=("https://developer.android.com/training/data-storage/shared-preferences",),
)
