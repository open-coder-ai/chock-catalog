"""A dependency version that is not pinned resolves again on every build, to whatever is newest."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.build._dependencies import declared

RULE_ID = "build-dynamic-version"

_FACTS = facts("build")["dynamic_version"]

_MESSAGE = (
    "This dependency's version floats ({version}) instead of naming one exact release, so the "
    "code compiled today can differ tomorrow with no change to this file, and a compromised "
    "release published under it reaches every build automatically. Pin an exact version number. "
    f"A dependency that must float for now needs 'chock: allow {RULE_ID}' on this line and a "
    "lockfile or verification step that would catch a bad resolve."
)

#: A Maven open-ended range: `[1.0,)` or `(,2.0)` -- one side names no bound at all.
_OPEN_RANGE = re.compile(r"[\[(]\s*,|,\s*[\])]$")


def _is_dynamic(version: str) -> bool:
    version = version.strip()
    if version.endswith("+"):
        return True
    if version.lower() in _FACTS["gradle_markers"]:
        return True
    if version in _FACTS["maven_tokens"]:
        return True
    return bool(_OPEN_RANGE.search(version)) and version[:1] in "[(" and version[-1:] in "])"


def scan(text: FileText) -> Iterator[Finding]:
    for dependency in declared(text):
        if _is_dynamic(dependency.version):
            message = _MESSAGE.format(version=dependency.version)
            yield Finding(RULE_ID, text.path, dependency.line_no, text.lines[dependency.line_no - 1], message)


RULE = Rule(
    id=RULE_ID,
    pack="build",
    title="Dependency pinned to a dynamic version",
    suffixes=(".xml", ".gradle", ".kts"),
    scan=scan,
    constraint=(
        "never(pin): a dependency version of +, latest.release, latest.integration, "
        "Maven LATEST/RELEASE, or an open range [1.0,) -- name one exact released version"
    ),
    refuses="a Gradle `+`/`latest.release`/`latest.integration` version; Maven `LATEST`/`RELEASE`/an open range",
    silent_on="a pinned exact version; a closed Maven range with both bounds named",
    cwe=("CWE-1357",),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html",
    ),
)
