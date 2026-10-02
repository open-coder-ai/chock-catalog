#!/usr/bin/env python3
"""Report registry, index and install settings that redirect where packages come from or weaken how they arrive."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The readers and the chock_scan copy ship beside this script. A missing copy raises here, and the
# runner treats an exit it did not ask for as undecided, which takes the declared action: never an
# allow. No bytecode cache is written: the gate is read_only in the repository it judges.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_scan.data_table import TableError  # noqa: E402 -- after the path and cache setup
from reg_core import ALLOWLIST, BLOCK, UNREADABLE, Ctx, add, digest  # noqa: E402
from reg_files import reader_for  # noqa: E402
from reg_hosts import REPO_LIST, committed, repo_entries, table  # noqa: E402
from reg_npm import pnpmfile  # noqa: E402

ALLOW, BLOCKED, FAULT, ASK = 0, 1, 2, 3
#: Registry configs are small; past this a file is not read but refused, keyed by its digest.
MAX_TEXT = 1 << 20
BOM = "\ufeff"
#: Past this many findings the document is one finding marked new: never compared, always judged.
MAX_FINDINGS = 5000
SHOWN = 50

ADVICE = (
    "Use https registries on the default hosts (or ones a person listed in .chock/registry-hosts.txt), "
    "keep TLS and checksum verification on, read tokens from environment references, and keep "
    "dependency install scripts off. A finding that only asks can be kept by a person committing from "
    "their own shell with CHOCK_ALLOW=registry-config for that one commit; an agent asks the person."
)


def _repo_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./")


def findings(payload: dict) -> list[dict]:
    """Every finding in the written files. The engine runs this again on the baseline text and judges
    only the keys the change holds more of."""
    writes = payload.get("writes")
    if not isinstance(writes, dict):
        raise TypeError("writes")
    out: list[dict] = []
    listed = sorted(
        (path, text) for path, text in writes.items() if isinstance(text, str) and _repo_path(path).lower() == REPO_LIST
    )
    if listed:
        # The allowlist itself changes in this write: what it now allows is a person's call, so it asks.
        path, text = listed[0]
        extra = repo_entries(text)
        ctx = Ctx(_repo_path(path), text)
        add(ctx, ALLOWLIST, 1, ("allowlist", digest(text)), "the registry host allowlist changes; a person reviews it")
        out += ctx.out
    else:
        extra = repo_entries(committed(str(payload.get("repo_root") or ".")))
    allow = table() + extra
    for path, text in sorted(writes.items()):
        reader = reader_for(str(path))
        if reader is None or not isinstance(text, str):
            continue
        # Every reader here (npm, Yarn, pip, TOML, YAML) drops a leading byte order mark, so the gate does too.
        ctx = Ctx(_repo_path(str(path)), text.removeprefix(BOM), allow)
        if len(text) > MAX_TEXT and reader is not pnpmfile:
            add(ctx, UNREADABLE, 1, ("size", digest(text)), f"larger than {MAX_TEXT} characters; not read")
        else:
            reader(ctx)
        out += ctx.out
    return out


def main() -> int:
    try:
        found = findings(json.load(sys.stdin))
    except TableError as exc:
        print(f"registry-config: the shipped host table cannot be used: {exc}", file=sys.stderr)
        return FAULT
    except (ValueError, TypeError, AttributeError, RecursionError):
        print("registry-config: stdin is not the gate JSON, or a file in it cannot be judged", file=sys.stderr)
        return FAULT
    if len(found) > MAX_FINDINGS:
        first = found[0]
        message = f"{len(found)} registry findings, more than {MAX_FINDINGS}: judged as new"
        found = [{**first, "key": "too-many", "rule": UNREADABLE, "message": message, "new": True}]
    print(json.dumps({"findings": found}))
    if not found:
        return ALLOW
    print("registry-config: this change redirects or weakens package installs:", file=sys.stderr)
    for item in found[:SHOWN]:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    return BLOCKED if any(item["rule"] in BLOCK for item in found) else ASK


if __name__ == "__main__":
    sys.exit(main())
