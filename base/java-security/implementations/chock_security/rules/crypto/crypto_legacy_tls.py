"""SSL and TLS below 1.2 carry known breaks (POODLE, BEAST) that a client cannot patch around."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "crypto-legacy-tls"

_FACTS = facts("crypto")["legacy_tls"]

_QUOTED = re.compile(r'"([^"]+)"')

_MESSAGE = (
    "{protocol} carries known, unpatchable breaks (POODLE, BEAST) and is disabled by every "
    'current TLS library for a reason. Use "TLS" (which negotiates the highest version both '
    f'sides support) or name "TLSv1.2"/"TLSv1.3" explicitly. \'chock: allow {RULE_ID}\' on this '
    "line if this is a compatibility shim you must keep for a legacy peer."
)


def _legacy_in(protocols: list[str]) -> str | None:
    return next((p for p in protocols if p in _FACTS["legacy_protocols"]), None)


def _quoted_protocols(line: str) -> list[str]:
    return _QUOTED.findall(line)


def _property_protocols(line: str) -> list[str]:
    if "=" not in line and ":" not in line:
        return []
    key, _, value = line.partition("=") if "=" in line else line.partition(":")
    if not any(marker.rstrip("=:") in key for marker in _FACTS["property_keys"]):
        return []
    return [token.strip().strip('"') for token in value.split(",") if token.strip()]


def _system_property_protocols(line: str) -> list[str]:
    """`System.setProperty("https.protocols", "TLSv1,TLSv1.1")` -- the key is one of its own args."""
    if "setProperty(" not in line:
        return []
    quoted = _QUOTED.findall(line)
    bare_keys = {marker.rstrip("=:") for marker in _FACTS["property_keys"]}
    if len(quoted) >= 2 and quoted[0] in bare_keys:
        return [token.strip() for token in quoted[1].split(",") if token.strip()]
    return []


def scan(text: FileText) -> Iterator[Finding]:
    """SSLContext.getInstance/setEnabledProtocols literals, and properties/YAML listing them."""
    for line_no, line in enumerate(text.lines, 1):
        protocols: list[str] = []
        if _FACTS["getinstance_marker"] in line or _FACTS["set_protocols_marker"] in line:
            protocols = _quoted_protocols(line)
        else:
            protocols = _system_property_protocols(line) or _property_protocols(line)
        legacy = _legacy_in(protocols)
        if legacy is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(protocol=legacy))


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Legacy SSL/TLS protocol version",
    suffixes=(".java", ".kt", ".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        'never(enable): SSLContext.getInstance|setEnabledProtocols|enabled-protocols with '
        '"SSL"|"SSLv2"|"SSLv3"|"TLSv1"|"TLSv1.1" -- use "TLS" or name "TLSv1.2"/"TLSv1.3"'
    ),
    refuses='SSLContext.getInstance/setEnabledProtocols/enabled-protocols naming SSL, SSLv2, SSLv3, TLSv1, or TLSv1.1',
    silent_on='"TLS", "TLSv1.2", "TLSv1.3"',
)
