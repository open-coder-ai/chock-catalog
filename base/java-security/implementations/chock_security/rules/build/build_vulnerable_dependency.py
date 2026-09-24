"""A declared dependency below the version that fixed a known, actively-exploited CVE in it."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.build import _versions
from chock_security.rules.build._dependencies import declared

RULE_ID = "build-vulnerable-dependency"

_ENTRIES = facts("build")["vulnerable_dependencies"]
_INDEX = {(entry["group"], entry["artifact"]): entry for entry in _ENTRIES}

_MESSAGE = (
    "{group}:{artifact} {version} carries {name} ({cve}); {fixed} is the first version without "
    "it. Raise the declared version to {fixed} or later. A pin that must stay on this version for "
    f"now needs 'chock: allow {RULE_ID}' on this line and a tracked upgrade, never a silent stay."
)


def _matching_range(entry: dict, version: str) -> dict | None:
    for candidate in entry["ranges"]:
        if _versions.gte(version, candidate["min"]) and _versions.lt(version, candidate["below"]):
            return candidate
    return None


def scan(text: FileText) -> Iterator[Finding]:
    for dependency in declared(text):
        entry = _INDEX.get((dependency.group, dependency.artifact))
        if entry is None:
            continue
        version = _versions.resolve(text, dependency.version)
        if version is None or version in entry.get("exceptions", ()):
            continue
        matched = _matching_range(entry, version)
        if matched is None:
            continue
        message = _MESSAGE.format(
            group=dependency.group, artifact=dependency.artifact, version=version,
            name=entry["name"], cve=entry["cve"], fixed=matched["below"],
        )
        yield Finding(RULE_ID, text.path, dependency.line_no, text.lines[dependency.line_no - 1], message)



def _ranges(entry: dict) -> str:
    return "|".join(r["min"] + "-<" + r["below"] if r["min"] != "0" else "<" + r["below"] for r in entry["ranges"])


#: Rendered from the table the scan reads, so the ambient line can never name a range it does not check.
_CONSTRAINT = (
    "never(declare): "
    + ", ".join(f"{e['artifact']} {_ranges(e)}" for e in _ENTRIES)
    + " -- raise to the first version that fixed the named CVE"
)


RULE = Rule(
    id=RULE_ID,
    pack="build",
    title="Dependency below the version that fixed a known-exploited CVE",
    suffixes=(".xml", ".gradle", ".kts"),
    scan=scan,
    constraint=_CONSTRAINT,
    refuses="a declared, resolvable version inside one of these ranges",
    silent_on="a version at or above the fix; a BOM-managed dependency with no explicit version; "
    "a version behind an unresolvable property",
)
