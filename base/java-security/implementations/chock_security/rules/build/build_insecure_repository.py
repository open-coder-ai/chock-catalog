"""A repository fetched over plain HTTP lets whoever sits on the network path swap the artifact."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "build-insecure-repository"

_FACTS = facts("build")["insecure_repository"]

_MESSAGE = (
    "This repository is fetched over plain HTTP, so a network attacker can substitute the jar "
    "or plugin before it reaches the build -- there is no channel integrity check behind it. "
    "Change the URL's scheme to https://; if the registry itself has no TLS endpoint, put one in "
    "front of it before a build points here. A mirror reachable only on an isolated network "
    f"needs 'chock: allow {RULE_ID}' on this line."
)

_POM_NAMES = frozenset({"pom.xml", "settings.xml"})
_GRADLE_NAMES = frozenset({"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"})
_WRAPPER_NAME = "gradle-wrapper.properties"


def _is_safe_host(line: str) -> bool:
    """A loopback URL never leaves the machine that built it, so it carries no network attacker."""
    return any(host in line for host in _FACTS["safe_hosts"])


def _http_url_lines(text: FileText) -> Iterator[int]:
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["scheme"] in line and not _is_safe_host(line):
            yield line_no


def _maven_lines(text: FileText) -> Iterator[int]:
    """Only a `<url>` inside a repository/mirror/distributionManagement block -- the same tag
    appears, harmlessly, on `<scm>` or `<issueManagement>` elsewhere in the same file. Tags are
    counted wherever they sit on the line, so `<repository>...</repository>` on one line opens
    and closes its block there."""
    names = tuple(_FACTS["maven_block_open"])
    opens = [re.compile(rf"<{re.escape(name)}(?=[\s>])") for name in names]
    closes = [f"</{name}>" for name in names]
    depth = 0
    for line_no, line in enumerate(text.lines, 1):
        depth += sum(len(pattern.findall(line)) for pattern in opens)
        if depth > 0 and _FACTS["maven_url_marker"] in line and _FACTS["scheme"] in line and not _is_safe_host(line):
            yield line_no
        depth = max(depth - sum(line.count(close) for close in closes), 0)


def _gradle_repo_lines(text: FileText) -> Iterator[int]:
    """A `maven { ... }` block, tracked by brace depth, with an http:// url inside it -- or the
    single-line form of the same thing written on one line."""
    marker = _FACTS["gradle_block_marker"]
    depth = 0
    for line_no, line in enumerate(text.lines, 1):
        for flag in _FACTS["gradle_flags"]:
            if flag in line:
                yield line_no
        opens_here = marker in line and "{" in line
        if opens_here:
            depth += 1
        if depth > 0 and _FACTS["scheme"] in line and not _is_safe_host(line):
            yield line_no
        depth += line.count("{") - line.count("}") - (1 if opens_here else 0)
        depth = max(depth, 0)


def _wrapper_lines(text: FileText) -> Iterator[int]:
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["wrapper_key"] in line and _FACTS["scheme"] in line and not _is_safe_host(line):
            yield line_no


def scan(text: FileText) -> Iterator[Finding]:
    name = PurePosixPath(text.path).name
    if text.suffix == ".xml" and name in _POM_NAMES:
        line_nos = _maven_lines(text)
    elif text.suffix in {".gradle", ".kts"} and name in _GRADLE_NAMES:
        line_nos = _gradle_repo_lines(text)
    elif text.suffix == ".properties" and name == _WRAPPER_NAME:
        line_nos = _wrapper_lines(text)
    else:
        return
    for line_no in sorted(set(line_nos)):
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="build",
    title="Build repository fetched over plain HTTP",
    suffixes=(".xml", ".gradle", ".kts", ".properties"),
    scan=scan,
    constraint=(
        "never(fetch): a repository/mirror/pluginRepository/distributionManagement url, or the "
        "wrapper distributionUrl, over http:// -- use https://, loopback URLs excepted"
    ),
    refuses="an http:// repository, mirror or wrapper URL; `allowInsecureProtocol = true`",
    silent_on="https:// URLs; http://localhost and http://127.0.0.1",
    cwe=("CWE-829", "CWE-494"),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html",
        "https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures/",
    ),
)
