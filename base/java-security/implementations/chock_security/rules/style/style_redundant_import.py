"""java.lang is imported by every class already; a duplicate or same-package import is dead text
that a reader has to double-check has no effect, for no benefit."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule

RULE_ID = "style-redundant-import"

_PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;")
_IMPORT = re.compile(r"^\s*import\s+(static\s+)?([\w.]+(?:\.\*)?)\s*;\s*$")

_MESSAGES = {
    "java.lang": "{fqcn} imports from java.lang, which every class can already see without an import.",
    "package": "{fqcn} imports a type from this file's own package ({package}), which needs no import.",
    "duplicate": "{fqcn} is imported again; it is already imported above.",
}


def _package_of(fqcn: str) -> str:
    if fqcn.endswith(".*"):
        return fqcn[:-2]
    return fqcn.rsplit(".", 1)[0] if "." in fqcn else ""


def _reason(fqcn: str, *, is_static: bool, package: str | None, seen: set) -> str | None:
    key = ("static", fqcn) if is_static else fqcn
    if key in seen:
        return "duplicate"
    if not is_static and _package_of(fqcn) == "java.lang":
        return "java.lang"
    if package is not None and _package_of(fqcn) == package:
        return "package"
    return None


def scan(text: FileText) -> Iterator[Finding]:
    lines = text.lines
    package = next((m.group(1) for line in lines if (m := _PACKAGE.match(line))), None)
    seen: set = set()
    for line_no, line in enumerate(lines, 1):
        match = _IMPORT.match(line)
        if not match:
            continue
        is_static, fqcn = bool(match.group(1)), match.group(2)
        reason = _reason(fqcn, is_static=is_static, package=package, seen=seen)
        seen.add(("static", fqcn) if is_static else fqcn)
        if reason is not None:
            message = _MESSAGES[reason].format(fqcn=fqcn, package=package)
            yield Finding(RULE_ID, text.path, line_no, line, message)


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="Redundant import",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(import): a java.lang type, a type from this file's own package, or the same import twice",
    refuses="`import java.lang.String;`, `import java.lang.*;`; a second `import` of the same name; a type "
    "imported from this file's own package",
    silent_on="`import static java.lang.Math.PI;`; imports from other packages, each written once",
    references=("https://checkstyle.org/checks/imports/redundantimport.html",),
)
