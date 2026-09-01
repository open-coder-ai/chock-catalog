"""Adopt a new framework (engine) version: rewrite the pin, regenerate, verify."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_REF_FILE = ROOT / ".framework-ref"


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

    if not FRAMEWORK_REF_FILE.exists():
        print(f"{FRAMEWORK_REF_FILE.name} not found; is the pin still wired? (ci.yml reads it)", file=sys.stderr)
        return 1
    if FRAMEWORK_REF_FILE.read_text(encoding="utf-8").strip() != args.ref:
        FRAMEWORK_REF_FILE.write_text(args.ref + "\n", encoding="utf-8", newline="\n")
        print(f"pinned framework ref: {args.ref}  (.framework-ref)")

    rc = 0
    rc = max(rc, _run("sync (recompile + hooks + index + lockfile)", ["chock", "sync", "--repo", "."]))
    rc = max(rc, _run("plugin packages", ["chock", "plugin", "build", "--repo", "."]))
    from trees import TREES

    for tree in TREES:
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
