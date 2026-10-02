"""MSBuild project files and Maven pom.xml, read with regular expressions (no XML parser on hostile input)."""

from __future__ import annotations

import hashlib
import html
import re

from lifecycle import ASK, BLOCK, Hit, norm
from lifecycle.signals import danger

#: A comment is blanked; a CDATA section is matched first so a `<!--` inside one stays text.
TRIVIA = re.compile(r"<!\[CDATA\[.*?\]\]>|<!--.*?(?:-->|\Z)", re.DOTALL)
ATTR = r"""\b{}\s*=\s*(?:"([^"]*)"|'([^']*)')"""
TARGET = re.compile(r"<Target\b([^>]*)>|</Target\s*>", re.IGNORECASE)
EXEC = re.compile(r"<Exec\b([^>]*)>", re.IGNORECASE)
IMPORT = re.compile(r"<Import\b([^>]*)>", re.IGNORECASE)
REMOTE = re.compile(r"(?i)^\s*(?:(?:https?|ftps?|file)://|\\\\|//)")
INLINE_TASK = re.compile(r"<UsingTask\b([^>]*)>(.*?)</UsingTask\s*>", re.IGNORECASE | re.DOTALL)
#: Target names MSBuild runs around a build on its own (Microsoft.Common.targets extension points).
HOOK_NAMES = {
    "beforebuild", "afterbuild", "beforecompile", "aftercompile", "beforerebuild", "afterrebuild",
    "beforeresolvereferences", "afterresolvereferences", "beforepublish", "afterpublish", "beforeclean",
    "afterclean", "beforerestore", "afterrestore",
}  # fmt: skip
PLUGIN = re.compile(r"<plugin\b[^>]*>(.*?)</plugin\s*>", re.IGNORECASE | re.DOTALL)
ARTIFACT = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
MAVEN_EXEC = {"exec-maven-plugin", "maven-antrun-plugin", "gmavenplus-plugin", "groovy-maven-plugin"}


def _code(text: str) -> str:
    """The text with XML comments blanked, offsets and line breaks kept."""
    return TRIVIA.sub(lambda m: m.group(0) if m.group(0).startswith("<![") else re.sub(r"[^\n]", " ", m.group(0)), text)


def _attr(attrs: str, name: str) -> str:
    found = re.search(ATTR.format(name), attrs, re.IGNORECASE)
    return html.unescape(next(g for g in found.groups() if g is not None)) if found else ""


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _targets(code: str) -> list[tuple[int, int, str]]:
    """(start, end, attributes) of each <Target>, closed by the next </Target> (MSBuild targets do not nest)."""
    spans, open_at, attrs = [], None, ""
    for match in TARGET.finditer(code):
        if match.group(0).startswith("</"):
            if open_at is not None:
                spans.append((open_at, match.end(), attrs))
            open_at = None
        else:
            open_at, attrs = match.start(), match.group(1)
    if open_at is not None:
        spans.append((open_at, len(code), attrs))
    return spans


def msbuild(text: str) -> list[Hit]:
    code = _code(text)
    project = re.search(r"<Project\b([^>]*)>", code, re.IGNORECASE)
    initial = {t.strip().lower() for t in _attr(project.group(1), "InitialTargets").split(";")} if project else set()
    initial.discard("")
    targets = _targets(code)
    hits = []
    for match in EXEC.finditer(code):
        command = _attr(match.group(1), "Command")
        attrs = next((a for start, end, a in targets if start <= match.start() < end), "")
        name = _attr(attrs, "Name")
        hooked = name.lower() in HOOK_NAMES | initial or bool(
            _attr(attrs, "BeforeTargets") or _attr(attrs, "AfterTargets")
        )
        why = danger(command) or ("runs on every build (hooked into the build)" if hooked else None)
        hits.append(
            Hit(
                _line(text, match.start()),
                "msbuild-exec",
                f"Target {name}",
                norm(command),
                BLOCK if why else ASK,
                why or "build target runs a command",
            )
        )
    for match in IMPORT.finditer(code):
        project_ref = _attr(match.group(1), "Project")
        if REMOTE.match(project_ref):
            hits.append(
                Hit(
                    _line(text, match.start()),
                    "msbuild-remote-import",
                    "Import",
                    norm(project_ref),
                    BLOCK,
                    "imports a project file from outside the repository",
                )
            )
    for match in INLINE_TASK.finditer(code):
        factory = _attr(match.group(1), "TaskFactory")
        if "codetaskfactory" in factory.lower():
            body = html.unescape(match.group(2))
            why = danger(body)
            digest = hashlib.sha256(norm(body).encode()).hexdigest()[:16]
            hits.append(
                Hit(
                    _line(text, match.start()),
                    "msbuild-inline-task",
                    _attr(match.group(1), "TaskName"),
                    digest,
                    BLOCK if why else ASK,
                    why or "inline C# task compiled and run by the build",
                )
            )
    return hits


def pom(text: str) -> list[Hit]:
    code = _code(text)
    hits = []
    for match in PLUGIN.finditer(code):
        body = match.group(1)
        artifact = ARTIFACT.search(body)
        name = artifact.group(1) if artifact else ""
        if name not in MAVEN_EXEC:
            continue
        why = danger(html.unescape(body))
        digest = hashlib.sha256(norm(body).encode()).hexdigest()[:16]
        hits.append(
            Hit(
                _line(text, match.start()),
                "maven-exec-plugin",
                name,
                digest,
                BLOCK if why else ASK,
                why or "the build runs a command or script through this plugin",
            )
        )
    return hits
