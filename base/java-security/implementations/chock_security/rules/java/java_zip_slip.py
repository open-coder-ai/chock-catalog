"""An archive entry's own name can be '../../etc/passwd'; nothing about extracting it stops that."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import methods
from chock_security.pack import Rule, facts

RULE_ID = "java-zip-slip"

_FACTS = facts("java")["zip_slip"]

_MESSAGE = (
    "This path is built from the archive entry's own name, and nothing in this method checks the "
    "result -- an entry named '../../etc/passwd' writes outside the directory you meant to "
    "extract into. Resolve the entry name against the destination directory, then check the "
    "resolved path still starts with that directory (or call toRealPath and compare) before "
    f"writing. An entry name already known to be safe needs 'chock: allow {RULE_ID}' on this line."
)


def _mentions_an_archive_entry(text: FileText) -> bool:
    """This rule reads only files that actually open an archive -- elsewhere `.getName()` is an
    ordinary getter this rule has no business judging."""
    return text.holds(*_FACTS["markers"])


def _method_checks_the_result(body_text: str) -> bool:
    to_real_path, normalize = _FACTS["hardening"]
    if to_real_path in body_text:
        return True
    return normalize in body_text and _FACTS["startswith_check"] in body_text


def scan(text: FileText) -> Iterator[Finding]:
    """Every path built from an archive entry's name, in a method that never checks it stays put."""
    if not _mentions_an_archive_entry(text):
        return
    for method in methods(text):
        body_text = "\n".join(line for _, line in method.body)
        if _method_checks_the_result(body_text):
            continue
        for line_no, line in method.body:
            if ".getName()" in line and any(call in line for call in _FACTS["path_calls"]):
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Zip slip: archive entry name used unchecked",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(extract): new File(dir, entry.getName())|Paths.get(dir).resolve(entry.getName()) "
        "with no .normalize()+.startsWith(dir) or .toRealPath() check in the method -- the entry "
        "name can be '../../etc/passwd'"
    ),
    refuses=(
        "a `new File`/`Paths.get`/`.resolve` built from a `ZipEntry`/`JarEntry`/`TarArchiveEntry` "
        "`.getName()`, in a method that never checks the resolved path stays inside the "
        "destination directory"
    ),
    silent_on=(
        "the same construction beside `.normalize()` and a `.startsWith()` check on the result; "
        "a `.toRealPath()` check; `.getName()` in a file that never opens an archive"
    ),
)
