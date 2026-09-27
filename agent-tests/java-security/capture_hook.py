"""Record one hook payload, exactly as the agent sent it, and let the call through.

Installed by `kit.py capture` beside chock's own hooks. It decides nothing: it appends the raw
payload to a log and exits 0 with no output, which every wired agent reads as "no objection".
Standard library only, so it runs under whatever interpreter the agent finds; it never raises,
because a hook that fails can block the agent it is only meant to watch.

    python capture_hook.py <log file> <agent>
"""

from __future__ import annotations

import contextlib
import json
import sys
from datetime import datetime, timezone


def record(raw: str, log: str, agent: str) -> None:
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    entry = {"agent": agent, "at": datetime.now(timezone.utc).isoformat(), "payload": payload}
    with open(log, "a", encoding="utf-8") as out:
        out.write(json.dumps(entry) + "\n")


def main(argv: list[str]) -> int:
    with contextlib.suppress(Exception):  # a watcher must never be why the agent stops
        record(sys.stdin.read(), argv[1], argv[2] if len(argv) > 2 else "?")  # noqa: PLR2004 -- argv shape
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
