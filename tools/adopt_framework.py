"""Adopt a new framework (engine) version: rewrite the pin, regenerate, verify."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

import framework_ref
import regen_all

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_REF_FILE = ROOT / framework_ref.PIN_FILE
ENGINE_URL = "https://github.com/open-coder-ai/chock"


def _run(label: str, cmd: list[str]) -> int:
    print(f"== {label}: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT).returncode


def installed_engine() -> str | None:
    """The commit the installed `chock` was built from, per its PEP 610 direct_url.json, or None.

    A git install records commit_id; a local-directory install (CI's `pip install ./.framework`) is
    identified by that checkout's HEAD while no tracked or untracked file differs from it (ignored
    build output, which the install itself writes, aside). A PyPI or unrecorded install is unidentified.
    """
    try:
        text = distribution("chock").read_text("direct_url.json")
    except PackageNotFoundError:
        return None
    try:
        origin = json.loads(text or "")
    except ValueError:
        return None
    if commit := (origin.get("vcs_info") or {}).get("commit_id"):
        return commit
    url = urlparse(origin.get("url", ""))
    if "dir_info" in origin and url.scheme == "file":
        return _checkout(url2pathname(url.path))
    return None


def _checkout(path: str) -> str | None:
    head = framework_ref._git(path, "rev-parse", "--verify", "HEAD^{commit}")
    status = framework_ref._git(path, "status", "--porcelain", "--untracked-files=all")
    if head.returncode or status.returncode or status.stdout:
        return None
    return head.stdout.strip()


def _engine_mismatch(ref: str) -> str | None:
    """Why the installed engine is not `ref` (pip skips a same-version reinstall), or None if it is."""
    found = installed_engine()
    if found == ref:
        return None
    return (
        f"the installed chock is {found or 'unidentified'}, not {ref}; install the engine being adopted:\n"
        f'  pip install --force-reinstall --no-deps "chock @ git+{ENGINE_URL}@{ref}"'
    )


def _pin(ref: str) -> int | None:
    """Write `ref` to the pin file; an exit code if it cannot be adopted."""
    # A branch or tag is a name the engine repo can repoint; only a commit SHA pins content.
    if not framework_ref.valid(ref):
        print(f"not a full 40-character lowercase commit SHA: {ref!r}", file=sys.stderr)
        return framework_ref.REFUSED
    if shutil.which("chock") is None:
        print("chock is not on PATH; install the target engine first (see module docstring).", file=sys.stderr)
        return 1
    if mismatch := _engine_mismatch(ref):
        print(mismatch, file=sys.stderr)
        return framework_ref.REFUSED
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

    from trees import TREES

    rc = 0
    for tree in TREES:
        if not (ROOT / tree).is_dir():
            print(f"tree listed by tools/trees.py is missing: {tree}", file=sys.stderr)
            rc = 1
    if rc:
        print("regeneration failed; fix before checking", file=sys.stderr)
        return rc
    # The same regeneration as tools/regen_all.py (registry, README counts, policy docs, figures), plus
    # what only an adoption rewrites: the installed packages, vendor hook configs, every transcript.
    rc = regen_all.regenerate("HEAD", adopt=True, transcripts=not args.skip_transcripts)
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
