"""Cleartext traffic permitted app-wide sends every request with no default host name to plain HTTP."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.android._network_config import base_config_lines

RULE_ID = "android-cleartext-traffic"

_FACTS = facts("android")["manifest"]

_MANIFEST_MESSAGE = (
    "android:usesCleartextTraffic=\"true\" lets this app make plain HTTP requests to any host with "
    "no per-domain override, so a network attacker on the same Wi-Fi reads and rewrites that "
    "traffic freely. Remove the attribute (the platform default is already false on API 28+) or "
    "supply a network security config naming the specific hosts, if any, that truly need it. A "
    f"transitional migration needs 'chock: allow {RULE_ID}' on this line and a tracked date to "
    "remove it."
)

_CONFIG_MESSAGE = (
    "cleartextTrafficPermitted=\"true\" on <base-config> allows plain HTTP to every domain this "
    "app talks to, not just the one this file was written for -- scope it to a <domain-config> "
    "naming that host instead, so every other destination still requires TLS. A base config that "
    f"truly must allow this everywhere needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    if PurePosixPath(text.path).name == _FACTS["file_name"]:
        for line_no, line in enumerate(text.lines, 1):
            if _FACTS["cleartext_manifest"] in line:
                yield Finding(RULE_ID, text.path, line_no, line, _MANIFEST_MESSAGE)
        return
    if text.suffix != ".xml":
        return
    base_lines = base_config_lines(text)
    for line_no, line in enumerate(text.lines, 1):
        if line_no in base_lines and _FACTS["cleartext_config_attr"] in line:
            yield Finding(RULE_ID, text.path, line_no, line, _CONFIG_MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="Cleartext traffic permitted app-wide",
    suffixes=(".xml",),
    scan=scan,
    constraint=(
        'never(set): android:usesCleartextTraffic="true" in AndroidManifest.xml, or '
        "cleartextTrafficPermitted=\"true\" on <base-config> -- scope it to a named <domain-config>"
    ),
    refuses='`usesCleartextTraffic="true"` in the manifest; `cleartextTrafficPermitted="true"` on `<base-config>`',
    silent_on='the manifest attribute set to `"false"` or absent; `cleartextTrafficPermitted="true"` inside a `<domain-config>`',
)
