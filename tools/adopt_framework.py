"""Adopt a new framework (engine) version: rewrite the pin, regenerate, verify."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import framework_ref

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_REF_FILE = ROOT / framework_ref.PIN_FILE


def _run(label: str, cmd: list[str]) -> int:
    print(f"== {label}: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT).returncode


def _pin(ref: str) -> int | None:
    """Write `ref` to the pin file; an exit code if it cannot be adopted."""
    # A branch or tag is a name the engine repo can repoint; only a commit SHA pins content.
    if not framework_ref.valid(ref):
        print(f"not a full 40-character lowercase commit SHA: {ref!r}", file=sys.stderr)
        return framework_ref.REFUSED
    if shutil.which("chock") is None:
        print("chock is not on PATH; install the target engine first (see module docstring).", file=sys.stderr)
        return 1
    if not FRAMEWORK_REF_FILE.exists():
        print(f"{FRAMEWORK_REF_FILE.name} not found; is the pin still wired? (ci.yml reads it)", file=sys.stderr)
        return 1
    if FRAMEWORK_REF_FILE.read_text(encoding="utf-8").strip() != ref:
        FRAMEWORK_REF_FILE.write_text(ref + "\n", encoding="utf-8", newline="\n")
        print(f"pinned framework ref: {ref}  (.framework-ref)")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Adopt a new framework version")
    parser.add_argument("ref", help="Framework commit to pin (full 40-character lowercase SHA)")
    parser.add_argument("--skip-transcripts", action="store_true", help="Skip re-adopting transcripts (slow step)")
    args = parser.parse_args(argv)

    if (refused := _pin(args.ref)) is not None:
        return refused

    rc = 0
    # Plugin packaging first: it writes plugin.json + skills/<id>/SKILL.md into each pack
    # directory it targets, including .agents/policies/<id> for a pack that has never had
    # those files generated there before. `sync` below regenerates chock.lock from whatever
    # is on disk at that point -- run after packaging, its lockfile hash covers the packaged
    # files too; run before (the old order), a first-time-packaged pack's lock entry is
    # written pre-packaging and `chock check` then reports a hash mismatch against files
    # sync never saw.
    rc = max(rc, _run("plugin packages", ["chock", "plugin", "build", "--repo", "."]))
    from trees import TREES

    for tree in TREES:
        if not (ROOT / tree).is_dir():
            print(f"tree listed by tools/trees.py is missing: {tree}", file=sys.stderr)
            rc = max(rc, 1)
            continue
        rc = max(rc, _run(f"plugin packages ({tree})", ["chock", "plugin", "build", "--repo", ".", "--policies-dir", tree]))
    rc = max(rc, _run("sync (recompile + hooks + index + lockfile)", ["chock", "sync", "--repo", "."]))
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
        rc = max(
            rc, _run("transcript reproducibility", [sys.executable, "tools/gen_adoption_transcript.py", "--check"])
        )

    print("ADOPTION " + ("CLEAN -- commit the diff as the adoption PR" if rc == 0 else "FAILED -- see above"))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
