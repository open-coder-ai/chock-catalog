#!/usr/bin/env python3
"""Report each known-malicious package version, action ref or IOC file name a write adds; the engine keeps the new ones."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The readers and the table ship beside this script. A missing or broken copy raises here, and the
# runner treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_scan import data_table
from iocscan import UnparseableError, route, table

ALTERNATIVE = (
    "Use a release outside the list (the cited advisory names the fixed one) or drop the dependency; pin "
    "a listed action to a reviewed 40-hex commit; delete an IOC file and treat the machine that wrote it "
    "as exposed. The list is data/ioc.json in this policy, changed only by a person in a reviewed pull "
    "request from the weekly threat digest; there is no in-line waiver."
)


def _why(entry: table.Entry) -> str:
    return f"{entry.incident}, {entry.date}, source {entry.source}"


def _finding(key: str, path: str, line: int, message: str) -> dict:
    return {"key": key, "path": path, "line": line, "message": message}


def _actions(ioc: table.Table, path: str, text: str) -> list[dict]:
    found = []
    for name, ref, line in route.uses(text):
        if entry := ioc.action(name, ref):
            msg = f"uses {name}@{ref}: a listed compromise of this action ({_why(entry)})"
            found.append(_finding(f"ioc-action|{name.casefold()}|{ref.casefold()}", path, line, msg))
    return found


def _packages(ioc: table.Table, path: str, text: str, reader: route.Reader) -> list[dict]:
    try:
        hits = list(reader(text))
    except UnparseableError as exc:
        return [_finding("unparseable", path, 1, f"cannot read this file to check it against the IOC list: {exc}")]
    found = []
    for hit in hits:
        if entry := ioc.package(hit.ecosystem, hit.name, hit.version):
            name = table.norm_name(hit.ecosystem, hit.name)
            version = "*" if hit.version is None else table.norm_version(hit.ecosystem, hit.version)
            shown = hit.name if hit.version is None else f"{hit.name}@{hit.version}"
            msg = f"{hit.ecosystem} {shown} is a known-malicious release ({_why(entry)})"
            found.append(_finding(f"ioc|{hit.ecosystem}|{name}|{version}", path, hit.line, msg))
    return found


def findings(payload: dict, ioc: table.Table) -> list[dict]:
    """Every listed package, action ref and file name in the writes, and every manifest it cannot read.

    A key names what is listed (ecosystem, normalised name, version), never a line, so the baseline
    run cancels what HEAD already held and a listed entry the change adds is new.
    """
    found = []
    for raw, text in sorted(payload.get("writes", {}).items()):
        path = raw.replace("\\", "/")
        if entry := ioc.file(path):
            found.append(
                _finding(f"ioc-file|{entry.name.casefold()}", path, 1, f"file name matches an IOC ({_why(entry)})")
            )
        if not isinstance(text, str):
            continue
        if route.is_workflow(path):
            found += _actions(ioc, path, text)
        if reader := route.reader(path):
            found += _packages(ioc, path, text, reader)
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("compromised-package-ioc: stdin is not the gate JSON", file=sys.stderr)
        return 2
    try:
        ioc = table.load()
    except data_table.TableError as exc:
        print(f"compromised-package-ioc: the IOC table cannot be used, so nothing is allowed: {exc}", file=sys.stderr)
        return 2
    found = findings(payload, ioc)
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("compromised-package-ioc: a write adds a known-malicious package, action ref or IOC file:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(ALTERNATIVE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
