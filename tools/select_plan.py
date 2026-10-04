#!/usr/bin/env python3
"""CI's plan for a pull request, as one line of JSON: a full run, or one job per policy it touches.

    python tools/select_plan.py origin/main

{"full": true}, or {"full": false, "policies": [job, ...], "tests": "files"}. A job is a policy the change
touches or that is built on one: its tests, the folder whose Python it gates at 100% coverage, and whether its
adoption transcript is checked. "tests" are the changed and always-run test files no job already runs.
Unsure is full, as in select_tests.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import select_tests as sel

#: More policies than this is a change to the catalog's core; one full run beats this many jobs.
MAX_POLICY_JOBS = 8


def implementations(root: Path, policy: Path) -> str:
    """The folder whose Python a policy job gates, or "" when it ships none."""
    impl = policy / "implementations"
    return impl.relative_to(root).as_posix() if any(impl.rglob("*.py")) else ""


def copies(root: Path, impl: str) -> list[str]:
    """Globs for the lib/ packages copied into `impl`: identical to lib/, which a full run gates."""
    lib = root / "lib"
    names = (
        sorted(p.name for p in lib.iterdir() if p.is_dir() and (root / impl / p.name).is_dir()) if lib.is_dir() else []
    )
    return [f"{impl}/{name}/**" for name in names]


def plan(root: Path, files: list[str]) -> dict:
    """{"full": True}, or one job per covered policy plus the tests none of those jobs runs."""
    found = sel.touches(root, files)
    covered = sel.dependents(root, found[0]) if found else set()
    if found is None or len(covered) > MAX_POLICY_JOBS:
        return {"full": True}
    folders = sel.policy_ids(root)
    owned = sel.owners(root)
    mine = {pid: {rel for rel, hit in owned.items() if pid in hit} for pid in covered}
    jobs = []
    for pid in sorted(covered):
        impl = implementations(root, folders[pid])
        jobs.append(
            {
                "policy": pid,
                "folder": folders[pid].relative_to(root).as_posix(),
                "implementations": impl,
                "omit": ",".join(copies(root, impl)) if impl else "",
                "transcript": pid in found[0],
                "tests": " ".join(sorted(mine[pid])),
            }
        )
    rest = (found[1] | {t for t in sel.ALWAYS if (root / t).is_file()}).difference(*mine.values())
    return {"full": False, "policies": jobs, "tests": " ".join(sorted(rest))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", help="the ref the PR targets, e.g. origin/main")
    args = parser.parse_args(argv)
    try:
        layout = plan(sel.ROOT, sel.changed_files(args.base, sel.ROOT))
    except (SystemExit, SyntaxError, OSError) as exc:
        print(f"{exc}; running everything.", file=sys.stderr)
        layout = {"full": True}
    print(json.dumps(layout, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
