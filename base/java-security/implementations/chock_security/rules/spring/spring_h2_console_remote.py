"""The H2 console lets whoever reaches it run arbitrary SQL; letting other hosts reach it removes
the only thing standing between the network and this database."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.spring._config import config_pairs, is_spring_config_file

RULE_ID = "spring-h2-console-remote"

_KEY = facts("spring")["h2_console"]["key"]

_MESSAGE = (
    "This lets any host that can reach this service open the H2 console and run arbitrary SQL "
    "against this database -- the console has no authentication of its own beyond the JDBC "
    "credentials it is handed. Remove this line (the default is false, console-local-only), or set "
    f"it to false; a debugging session that truly needs it needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """`spring.h2.console.settings.web-allow-others` set true, in main application config."""
    if not is_spring_config_file(text.path):
        return
    for entry in config_pairs(text):
        if entry.key == _KEY and entry.value.strip().lower() == "true":
            yield Finding(RULE_ID, text.path, entry.line_no, text.lines[entry.line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="H2 console reachable from other hosts",
    suffixes=(".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        "never(set): spring.h2.console.settings.web-allow-others=true "
        "-- the H2 console runs arbitrary SQL with no auth of its own; leave it false"
    ),
    refuses="spring.h2.console.settings.web-allow-others=true",
    silent_on="the key set to false, or absent (the framework default)",
    cwe=("CWE-306",),
    references=("https://nvd.nist.gov/vuln/detail/CVE-2022-23221",),
)
