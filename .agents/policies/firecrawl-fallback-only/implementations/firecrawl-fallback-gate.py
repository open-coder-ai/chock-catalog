"""Warn on a Firecrawl call when no native fetch has failed earlier in this session."""

from __future__ import annotations

import importlib
import json
import os
import sys

NATIVE = ("WebFetch", "WebSearch")
CLI_FETCHERS = ("curl", "wget")
WHY = (
    "firecrawl is a fallback: no failed WebFetch, WebSearch, curl or wget call is on record in this session. "
    "Try a native fetch first; if the page is blocked, JS-only or rate limited, go on and note that reason."
)


def load_log(root: str):
    """The vendored session reader, or None when this install has none."""
    sys.path.insert(0, os.path.join(root, ".chock", "bin"))
    try:
        return importlib.import_module("chock_session")
    except ImportError:
        return None


def cli_fetch_failed(log, records) -> bool:
    """Whether a Bash curl or wget call finished in error."""
    for record in log.matching(records, tool="Bash", phase=log.POST, outcome=log.ERROR):
        words = str((record.get("input") or {}).get("command", "")).split()
        if words and os.path.basename(words[0]) in CLI_FETCHERS:
            return True
    return False


def native_failed(log, records) -> bool:
    return any(log.failed(records, tool=tool) for tool in NATIVE) or cli_fetch_failed(log, records)


def main() -> int:
    payload = json.load(sys.stdin)
    log = load_log(str(payload.get("repo_root", ".")))
    if log and native_failed(log, log.prior(payload.get("session") or {})):
        return 0
    sys.stderr.write(WHY)
    return 4


if __name__ == "__main__":
    sys.exit(main())
