"""Adopt a new framework (engine) version: rewrite the pin, regenerate, verify.

A version bump in this repo is never just a version number -- the catalog commits
derived output (compiled artifacts, plugin packages, docs, adoption transcripts),
and CI verifies all of it against the pinned engine. This tool makes adoption one
command instead of a red-CI scavenger hunt:

    # 1. install the target engine locally (pre-launch: editable from the framework
    #    checkout at the target tag; post-launch: pip install chock==X.Y.Z)
    # 2. run:
    python tools/adopt_framework.py rc/0.1.0-rc.2

It rewrites FRAMEWORK_REF in ci.yml, regenerates everything, and runs every check.
Commit the whole diff as the adoption PR. If the engine's emitters changed (a MINOR
framework release), the diff shows exactly what changed about enforcement.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"


def _run(label: str, cmd: list[str]) -> int:
    print(f"== {label}: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Adopt a new framework version")
    parser.add_argument("ref", help="Framework ref to pin (git tag pre-launch; version post-launch)")
    parser.add_argument("--skip-transcripts", action="store_true", help="Skip re-adopting transcripts (slow step)")
    args = parser.parse_args(argv)

    if shutil.which("chock") is None:
        print("chock is not on PATH; install the target engine first (see module docstring).", file=sys.stderr)
        return 1

    text = CI_YML.read_text(encoding="utf-8")
    new_text, n = re.subn(r"(FRAMEWORK_REF: ).*", rf"\g<1>{args.ref}", text, count=1)
    if n != 1:
        print("FRAMEWORK_REF not found in ci.yml; is the pin still wired?", file=sys.stderr)
        return 1
    if new_text != text:
        CI_YML.write_text(new_text, encoding="utf-8", newline="\n")
        print(f"pinned FRAMEWORK_REF: {args.ref}")

    rc = 0
    rc = max(rc, _run("sync (recompile + hooks + index + lockfile)", ["chock", "sync", "--repo", "."]))
    rc = max(rc, _run("plugin packages", ["chock", "plugin", "build", "--repo", "."]))
    # The PUBLISHED trees too, exactly as CI checks them per-tree. The plain build above
    # covers only .agents/policies (what this repo runs); an engine whose emitter output
    # changed leaves every base/<id> package stale, which then fails the transcript step:
    # a fresh adoption copies the stale package and `chock check` reports plugin_drift.
    # Found by the first emitter-changing adoption (framework copilot-format bump).
    from trees import TREES

    for tree in TREES:
        # A listed tree with no directory is a failure, not a skip: CI's staging step
        # errors on exactly this ("tree listed by tools/trees.py is missing"), and an
        # adoption that silently skipped one would report CLEAN on an incomplete set.
        if not (ROOT / tree).is_dir():
            print(f"tree listed by tools/trees.py is missing: {tree}", file=sys.stderr)
            rc = max(rc, 1)
            continue
        rc = max(rc, _run(f"plugin packages ({tree})", ["chock", "plugin", "build", "--repo", ".", "--policies-dir", tree]))
    rc = max(rc, _run("policy docs", [sys.executable, "tools/gen_policy_docs.py"]))
    rc = max(rc, _run("coverage matrix", [sys.executable, "tools/gen_coverage_matrix.py"]))
    if not args.skip_transcripts:
        rc = max(rc, _run("adoption transcripts", [sys.executable, "tools/gen_adoption_transcript.py"]))
    if rc:
        print("regeneration failed; fix before checking", file=sys.stderr)
        return rc

    for label, cmd in [
        ("check", ["chock", "check"]),
        ("plugin freshness", ["chock", "plugin", "build", "--check"]),
        ("readme claims", [sys.executable, "tools/check_readme.py"]),
        ("console transcripts", [sys.executable, "tools/check_console.py"]),
        ("workflow safety", [sys.executable, "tools/check_workflows.py"]),
    ]:
        rc = max(rc, _run(label, cmd))
    if not args.skip_transcripts:
        rc = max(rc, _run("transcript reproducibility", [sys.executable, "tools/gen_adoption_transcript.py", "--check"]))

    print("ADOPTION " + ("CLEAN -- commit the diff as the adoption PR" if rc == 0 else "FAILED -- see above"))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
