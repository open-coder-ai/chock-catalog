"""Turning Micronaut security off in the main config leaves every endpoint unauthenticated."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.jakarta._config import flat_value, not_spring, yaml_value

RULE_ID = "jakarta-security-disabled"

_FACTS = facts("jakarta")["security_disabled"]

_MESSAGE = (
    "This turns Micronaut security off for the whole application, so every endpoint -- including "
    "ones that assume @Secured is enforced -- serves any caller. Leave it enabled and secure "
    "individual endpoints with @Secured(\"anonymous\") where they must be public."
)


def _main_config(text: FileText) -> bool:
    """The main application config, not a test-only resource this could reasonably disable in."""
    lower = text.path.lower()
    return "test" not in lower


def scan(text: FileText) -> Iterator[Finding]:
    """`micronaut.security.enabled=false` in the application's own configuration."""
    if not not_spring(text) or not _main_config(text):
        return
    reader = flat_value if text.suffix == ".properties" else yaml_value
    for line_no, line, value in reader(text, _FACTS["micronaut_key"]):
        if value == _FACTS["false_value"]:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="Micronaut security disabled",
    suffixes=(".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        "never(disable): micronaut.security.enabled=false in application config "
        "-- leave security enabled, secure individual endpoints with @Secured"
    ),
    refuses="`micronaut.security.enabled=false` in the main application config",
    silent_on="security left enabled or unset; the same key in a file whose path names it as test",
)
