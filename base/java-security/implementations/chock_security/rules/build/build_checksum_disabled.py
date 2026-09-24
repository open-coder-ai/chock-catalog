"""Turning checksum verification off installs whatever bytes arrived, corrupted or substituted."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "build-checksum-disabled"

_FACTS = facts("build")["checksum_disabled"]

_MESSAGE = (
    "This turns off the last check between the registry and the classpath: a corrupted download "
    "or a substituted artifact now installs silently instead of failing the build. Remove the "
    "override -- Maven's checksumPolicy defaults to fail, and Gradle's dependency verification "
    f"should stay strict. A registry with no checksums at all needs 'chock: allow {RULE_ID}' "
    "on this line and a plan to get one that publishes them."
)

_GRADLE_OFF = re.compile(rf"{re.escape(_FACTS['gradle_key'])}\s*=\s*{re.escape(_FACTS['gradle_disabled_value'])}\b")


def scan(text: FileText) -> Iterator[Finding]:
    name = PurePosixPath(text.path).name
    if text.suffix == ".xml" and name in {"pom.xml", "settings.xml"}:
        for line_no, line in enumerate(text.lines, 1):
            if _FACTS["maven_disabled"] in line:
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)
    elif text.suffix == ".properties" and name == "gradle.properties":
        for line_no, line in enumerate(text.lines, 1):
            if _GRADLE_OFF.search(line):
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="build",
    title="Dependency checksum verification disabled",
    suffixes=(".xml", ".properties"),
    scan=scan,
    constraint=(
        "never(disable): maven <checksumPolicy>ignore</checksumPolicy>; "
        "gradle org.gradle.dependency.verification=off -- keep checksums enforced"
    ),
    refuses="Maven `checksumPolicy` set to `ignore`; Gradle dependency verification set to `off`",
    silent_on="`checksumPolicy` left at `fail` or set to `warn`; verification left at `strict`/`lenient`",
    cwe=("CWE-353", "CWE-494"),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html",
    ),
)
