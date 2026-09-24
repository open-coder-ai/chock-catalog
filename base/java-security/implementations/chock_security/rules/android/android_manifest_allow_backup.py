"""allowBackup with no backup rules lets adb backup (and OEM auto-backup) copy every app file off device."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "android-manifest-allow-backup"

_FACTS = facts("android")["manifest"]

_MESSAGE = (
    "android:allowBackup=\"true\" with no android:fullBackupContent or android:dataExtractionRules "
    "means adb backup (with no root, over USB, on any pre-Android-12 device with debugging on) "
    "and the OEM's cloud auto-backup both copy every file this app owns, including session "
    "tokens and databases -- there is no rule here narrowing what gets copied. Add "
    "android:fullBackupContent (or android:dataExtractionRules on API 31+) naming what may be "
    f"backed up, or set allowBackup to false. An app with nothing sensitive on disk needs 'chock: "
    f"allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    if PurePosixPath(text.path).name != _FACTS["file_name"]:
        return
    if text.holds(*_FACTS["backup_rules_markers"]):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["allow_backup_true"] in line:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="allowBackup enabled with no backup rules",
    suffixes=(".xml",),
    scan=scan,
    constraint=(
        'never(set): android:allowBackup="true" in AndroidManifest.xml with no '
        "fullBackupContent/dataExtractionRules -- name what may be backed up, or turn backup off"
    ),
    refuses='`allowBackup="true"` in a manifest naming no fullBackupContent/dataExtractionRules',
    silent_on='`allowBackup="false"`; `allowBackup="true"` alongside either backup-rules attribute',
)
