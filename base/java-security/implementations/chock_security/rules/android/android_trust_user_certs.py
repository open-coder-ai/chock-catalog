"""Trusting user-installed CAs app-wide lets a device profile or MDM certificate intercept TLS."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.android._network_config import base_config_lines

RULE_ID = "android-trust-user-certs"

_FACTS = facts("android")["manifest"]

_MESSAGE = (
    "This trusts user-installed certificates for every domain the app talks to, so any "
    "certificate a person is convinced (or an MDM is configured) to install becomes a valid TLS "
    "endpoint for this app's traffic -- exactly the setup an interception proxy relies on. Scope "
    "the user trust anchor to a <domain-config> for the one host that genuinely needs it (a "
    "debug proxy target, say), and leave <base-config> on the system trust store alone. A "
    f"deliberate app-wide exception needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    if text.suffix != ".xml":
        return
    base_lines = base_config_lines(text)
    for line_no, line in enumerate(text.lines, 1):
        if (
            line_no in base_lines
            and _FACTS["trust_user_certs_marker"] in line
            and _FACTS["trust_user_certs_value"] in line
        ):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="User-installed CAs trusted app-wide",
    suffixes=(".xml",),
    scan=scan,
    constraint=(
        'never(trust): <certificates src="user" /> inside <base-config> in a network security '
        "config -- scope the user trust anchor to a named <domain-config> instead"
    ),
    refuses='`<certificates src="user" />` inside `<base-config>`',
    silent_on='the same element inside a `<domain-config>`; `src="system"`',
    cwe=("CWE-295",),
    references=("https://developer.android.com/privacy-and-security/security-config",),
)
