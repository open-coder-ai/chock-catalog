"""Finds a declared dependency's group, artifact and version token, whichever build file it is in.

Every form is read literally, line by line, never across an unrelated block: a `<dependency>`
element in a pom, a Gradle string `"group:artifact:version"` (Groovy or Kotlin DSL, single- or
double-quoted), and a single-line Gradle map `group: 'g', name: 'a', version: 'v'`. A dependency
this cannot read this plainly -- a multi-line map, a version catalog alias, anything assembled at
build time -- is left out rather than guessed, so a rule built on this stays silent on it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

from chock_security.decision import FileText

POM_NAMES = frozenset({"pom.xml"})
GRADLE_BUILD_NAMES = frozenset({"build.gradle", "build.gradle.kts"})


@dataclass(frozen=True)
class Declared:
    """One dependency coordinate, as one file states it, with the line its version sits on."""

    group: str
    artifact: str
    version: str
    line_no: int


_DEP_OPEN = "<dependency>"
_DEP_CLOSE = "</dependency>"
_GROUP = re.compile(r"<groupId>\s*([^<]+?)\s*</groupId>")
_ARTIFACT = re.compile(r"<artifactId>\s*([^<]+?)\s*</artifactId>")
_VERSION = re.compile(r"<version>\s*([^<]+?)\s*</version>")


def _maven(text: FileText) -> Iterator[Declared]:
    """Every `<dependency>` block that states its own `<version>` -- a BOM-managed one, with no
    version in the block at all, is exactly the case a caller must stay silent on, so it is
    simply never produced here.
    """
    group = artifact = version = None
    version_line = 0
    inside = False
    for line_no, line in enumerate(text.lines, 1):
        if _DEP_OPEN in line:
            inside, group, artifact, version = True, None, None, None
            continue
        if not inside:
            continue
        if _DEP_CLOSE in line:
            if group and artifact and version:
                yield Declared(group, artifact, version, version_line)
            inside = False
            continue
        if match := _GROUP.search(line):
            group = match.group(1)
        if match := _ARTIFACT.search(line):
            artifact = match.group(1)
        if match := _VERSION.search(line):
            version, version_line = match.group(1), line_no


#: `"group:artifact:version"` -- the colon-separated triple both Groovy and Kotlin DSL quote the
#: same way. The version half excludes ':' and the closing quote, so a URL or anything else with
#: more than two colons in one quoted string simply fails to match, rather than matching wrong.
_GRADLE_STRING = re.compile(r"""(['"])([\w][\w.\-]*):([\w][\w.\-]*):([^'"\s]+)\1""")


def _gradle_strings(text: FileText) -> Iterator[Declared]:
    for line_no, line in enumerate(text.lines, 1):
        for match in _GRADLE_STRING.finditer(line):
            yield Declared(match.group(2), match.group(3), match.group(4), line_no)


def _kv(line: str, key: str) -> str | None:
    match = re.search(rf"\b{key}\s*:\s*['\"]([^'\"]+)['\"]", line)
    return match.group(1) if match else None


def _gradle_maps(text: FileText) -> Iterator[Declared]:
    """The single-line map form only -- one spread across several lines is left unread rather
    than guessed at, which is the same choice the pom reader makes for a managed version.
    """
    for line_no, line in enumerate(text.lines, 1):
        group, name, version = _kv(line, "group"), _kv(line, "name"), _kv(line, "version")
        if group and name and version:
            yield Declared(group, name, version, line_no)


def declared(text: FileText) -> Iterator[Declared]:
    """Every dependency this file states plainly, in whichever form its file type uses."""
    name = PurePosixPath(text.path).name
    if text.suffix == ".xml" and name in POM_NAMES:
        yield from _maven(text)
        return
    if text.suffix in {".gradle", ".kts"} and name in GRADLE_BUILD_NAMES:
        yield from _gradle_strings(text)
        yield from _gradle_maps(text)
