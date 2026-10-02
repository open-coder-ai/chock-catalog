"""MSBuild project files and Maven pom.xml, read with regular expressions (no XML parser on hostile input).

Every scan is one forward pass: blocks pair an opening tag with the next closing one, and line numbers
come from one index, so a file of unclosed tags stays linear.
"""

from __future__ import annotations

import hashlib
import html
import re
from bisect import bisect_right
from collections.abc import Callable

from lifecycle import ASK, BLOCK, Hit, norm
from lifecycle.signals import danger

#: A comment is blanked; a CDATA section is matched first so a `<!--` inside one stays text.
TRIVIA = re.compile(r"<!\[CDATA\[.*?(?:\]\]>|\Z)|<!--.*?(?:-->|\Z)", re.DOTALL)
#: Attributes in document order, so `Command=` inside another attribute's quoted value is that value's text.
ATTRS = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
EXEC = re.compile(r"<Exec\b([^>]*)>", re.IGNORECASE)
IMPORT = re.compile(r"<Import\b([^>]*)>", re.IGNORECASE)
DOWNLOAD = re.compile(r"<DownloadFile\b([^>]*)>", re.IGNORECASE)
REMOTE = re.compile(r"(?i)^\s*(?:(?:https?|ftps?|file)://|\\\\|//)")
#: Target names MSBuild runs around a build on its own (Microsoft.Common.targets extension points).
HOOK_NAMES = {
    "beforebuild", "afterbuild", "beforecompile", "aftercompile", "beforerebuild", "afterrebuild",
    "beforeresolvereferences", "afterresolvereferences", "beforepublish", "afterpublish", "beforeclean",
    "afterclean", "beforerestore", "afterrestore",
}  # fmt: skip
ARTIFACT = re.compile(r"<artifactId\s*>\s*([^<]*?)\s*</artifactId\s*>", re.IGNORECASE)
MAVEN_EXEC = {"exec-maven-plugin", "maven-antrun-plugin", "gmavenplus-plugin", "groovy-maven-plugin"}


def _code(text: str) -> str:
    """The text with XML comments blanked, offsets and line breaks kept."""
    return TRIVIA.sub(lambda m: m.group(0) if m.group(0).startswith("<![") else re.sub(r"[^\n]", " ", m.group(0)), text)


def _attrs(tag: str) -> dict[str, str]:
    """Attribute name (lower-case) -> unescaped value; the first spelling of a name wins."""
    found: dict[str, str] = {}
    for match in ATTRS.finditer(tag):
        value = match.group(2) if match.group(2) is not None else match.group(3)
        found.setdefault(match.group(1).lower(), html.unescape(value))
    return found


def _liner(text: str) -> Callable[[int], int]:
    """Offset -> 1-based line number, from one pass over the text."""
    ends = [m.end() for m in re.finditer("\n", text)]
    return lambda offset: bisect_right(ends, offset) + 1


def _blocks(code: str, tag: str) -> list[tuple[int, int, str, str]]:
    """(start, end, opening-tag attributes, body) of each <tag>, closed by the next </tag> (none nest here)."""
    found, open_at = [], None
    for match in re.finditer(rf"<{tag}\b([^>]*)>|</{tag}\s*>", code, re.IGNORECASE):
        if match.group(0).startswith("</"):
            if open_at is not None:
                found.append((open_at.start(), match.end(), open_at.group(1), code[open_at.end() : match.start()]))
            open_at = None
        else:
            open_at = match
    if open_at is not None:
        found.append((open_at.start(), len(code), open_at.group(1), code[open_at.end() :]))
    return found


def msbuild(text: str) -> list[Hit]:
    code, line = _code(text), _liner(text)
    project = re.search(r"<Project\b([^>]*)>", code, re.IGNORECASE)
    initial = {
        t.strip().lower() for t in _attrs(project.group(1) if project else "").get("initialtargets", "").split(";")
    }
    initial.discard("")
    targets = _blocks(code, "Target")
    starts = [t[0] for t in targets]
    hits = []

    def target_of(offset: int) -> dict[str, str]:
        index = bisect_right(starts, offset) - 1
        return _attrs(targets[index][2]) if index >= 0 and offset < targets[index][1] else {}

    for match in EXEC.finditer(code):
        command, target = _attrs(match.group(1)).get("command", ""), target_of(match.start())
        name = target.get("name", "")
        hooked = name.lower() in HOOK_NAMES | initial or bool(target.get("beforetargets") or target.get("aftertargets"))
        why = danger(command) or ("runs on every build (hooked into the build)" if hooked else None)
        hits.append(Hit(line(match.start()), "msbuild-exec", f"Target {name}", norm(command), BLOCK if why else ASK,
                        why or "build target runs a command"))  # fmt: skip
    for match in IMPORT.finditer(code):
        ref = _attrs(match.group(1)).get("project", "")
        if REMOTE.match(ref):
            hits.append(Hit(line(match.start()), "msbuild-remote-import", "Import", norm(ref), BLOCK,
                            "imports a project file from outside the repository"))  # fmt: skip
    for match in DOWNLOAD.finditer(code):
        url = _attrs(match.group(1)).get("sourceurl", "")
        hits.append(Hit(line(match.start()), "msbuild-download", "DownloadFile", norm(url), BLOCK,
                        "the build downloads a file (DownloadFile task)"))  # fmt: skip
    for start, _end, attrs, body in _blocks(code, "UsingTask"):
        task = _attrs(attrs)
        if "codetaskfactory" in task.get("taskfactory", "").lower():
            why = danger(html.unescape(body))
            digest = hashlib.sha256(norm(body).encode()).hexdigest()[:16]
            hits.append(Hit(line(start), "msbuild-inline-task", task.get("taskname", ""), digest,
                            BLOCK if why else ASK, why or "inline C# task compiled and run by the build"))  # fmt: skip
    return hits


def pom(text: str) -> list[Hit]:
    """A plugin block naming a command-running plugin among any of its artifactIds (entities decoded)."""
    code, line = _code(text), _liner(text)
    hits = []
    for start, _end, _tag, body in _blocks(code, "plugin"):
        found = sorted({html.unescape(m.group(1)).strip() for m in ARTIFACT.finditer(body)} & MAVEN_EXEC)
        if not found:
            continue
        why = danger(html.unescape(body))
        digest = hashlib.sha256(norm(body).encode()).hexdigest()[:16]
        hits.append(Hit(line(start), "maven-exec-plugin", found[0], digest, BLOCK if why else ASK,
                        why or "the build runs a command or script through this plugin"))  # fmt: skip
    return hits
