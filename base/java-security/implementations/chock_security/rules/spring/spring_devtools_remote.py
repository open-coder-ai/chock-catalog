"""Remote DevTools accepts a class-reload payload over HTTP once its secret is known -- and that
secret is the one thing standing between a caller and running arbitrary code in this process."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.spring._config import config_pairs, is_spring_config_file, is_test_resource

_KEY = facts("spring")["devtools"]["key"]

RULE_ID = "spring-devtools-remote"

_MESSAGE = (
    "This turns on remote DevTools, which accepts a class-reload payload over HTTP from anyone who "
    "knows this secret -- and that makes it a remote-code-execution endpoint in production. Remote "
    "DevTools is meant for a local tunnel to a development server only; remove this line from any "
    "config that reaches production, and never enable the devtools dependency there either."
)


def scan(text: FileText) -> Iterator[Finding]:
    """spring.devtools.remote.secret set, in main (non-test) application configuration."""
    if not is_spring_config_file(text.path) or is_test_resource(text.path):
        return
    for entry in config_pairs(text):
        if entry.key == _KEY and entry.value.strip():
            yield Finding(RULE_ID, text.path, entry.line_no, text.lines[entry.line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Remote DevTools enabled",
    suffixes=(".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        "never(set): spring.devtools.remote.secret=<value> in application/bootstrap config "
        "-- remote DevTools accepts a class-reload payload once the secret is known; keep it local-only"
    ),
    refuses="spring.devtools.remote.secret set to a non-empty value in main application config",
    silent_on="the key absent, an empty value, and test resources",
    cwe=("CWE-489",),
    references=("https://docs.spring.io/spring-boot/reference/using/devtools.html",),
)
