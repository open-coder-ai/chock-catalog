"""A manifest shipped with android:debuggable="true" lets any app attach a debugger to it in production."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "android-manifest-debuggable"

_FACTS = facts("android")["manifest"]

_MESSAGE = (
    'android:debuggable="true" lets any app on the device (or anyone with a USB cable) attach a '
    "debugger, dump memory and step through this app's code -- Gradle sets this flag itself from "
    "the build type, so writing it in the manifest freezes it on regardless of build type. Remove "
    f"the attribute and let debuggable follow the debug build type instead. A manifest for a "
    f"debug-only source set that truly ships nowhere needs 'chock: allow {RULE_ID}' on this line."
)


def _is_debug_source_set(path: str) -> bool:
    """A manifest under a `debug`/`debugXxx` source set is merged only into the debug build,
    where this flag is the normal, intended value -- flagging it there is exactly the false
    positive this pack exists to avoid."""
    directories = PurePosixPath(path).parts[:-1]
    return any(part.lower().startswith("debug") for part in directories)


def scan(text: FileText) -> Iterator[Finding]:
    if PurePosixPath(text.path).name != _FACTS["file_name"] or _is_debug_source_set(text.path):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["debuggable_true"] in line:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="AndroidManifest.xml marked debuggable",
    suffixes=(".xml",),
    scan=scan,
    constraint=(
        'never(set): android:debuggable="true" in AndroidManifest.xml '
        "-- let the build type control it, never the manifest"
    ),
    refuses='`android:debuggable="true"` outside a debug source set',
    silent_on='`android:debuggable="false"`; the attribute absent; a manifest under `src/debug/`',
)
