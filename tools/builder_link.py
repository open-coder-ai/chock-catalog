#!/usr/bin/env python3
"""The chock.sh builder deep link of a policy page: its share code, its catalog ref and the drift check on both."""

from __future__ import annotations

import base64
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from chock.lock import compute_pack_hash
from trees import ROOT, policy_dirs

DOCS = ROOT / "docs"
BUILDER = "https://chock.sh/coding/builder/"
CATALOG_SOURCE = "https://github.com/open-coder-ai/chock-catalog"
LINK_RE = re.compile(re.escape(BUILDER) + r"#s=([A-Za-z0-9_-]+)")


def selection_code(policy_id: str, version: str, sha256: str, ref: str) -> str:
    """The builder's share code: the compact schema-2 selection of one policy for Claude Code, base64url, unpadded."""
    selection = {
        "schema": 2,
        "client": "claude-code",
        "bundle": {"version": "1.0.0"},
        "catalog": {"source": CATALOG_SOURCE, "ref": ref},
        "policies": [{"from": "catalog", "id": policy_id, "version": version, "sha256": sha256}],
    }
    raw = json.dumps(selection, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_code(code: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(code + "=" * (-len(code) % 4)))


def _git(*args: str) -> str | None:
    """Stdout of a git command run in the checkout, None when git fails."""
    try:
        done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout.strip()


def _folder_ref(policy_dir: Path) -> str | None:
    """The newest commit that touched the folder, when the folder is unmodified against it."""
    rel = policy_dir.relative_to(ROOT).as_posix()
    if _git("status", "--porcelain", "--", rel) != "":
        return None
    return _git("log", "-1", "--format=%H", "--", rel) or None


def _pinned_ref(page: Path, policy_id: str, version: str, sha256: str) -> str | None:
    """The ref the page already pins, while its policy version and pack hash are unchanged."""
    match = LINK_RE.search(page.read_text(encoding="utf-8")) if page.exists() else None
    pinned = _decode_or_none(match.group(1)) if match else None
    entry = (pinned or {}).get("policies", [{}])[0]
    same = (entry.get("id"), entry.get("version"), entry.get("sha256")) == (policy_id, version, sha256)
    return pinned["catalog"]["ref"] if pinned and same else None


def _decode_or_none(code: str) -> dict | None:
    """The decoded selection, None when the code is not a selection."""
    try:
        decoded = decode_code(code)
    except ValueError:
        return None
    return decoded if isinstance(decoded, dict) else None


def catalog_ref(page: Path, policy_dir: Path, version: str, sha256: str, *, keep_pinned: bool) -> str:
    """A commit that holds the pack: the folder's last commit, else the page's pin, else the checkout's HEAD.

    `keep_pinned` ranks the page's own pin first, so `--check` ignores the ref and a shallow clone cannot fail it.
    """
    pinned = _pinned_ref(page, policy_dir.name, version, sha256)
    candidates = [pinned, _folder_ref(policy_dir)] if keep_pinned else [_folder_ref(policy_dir), pinned]
    ref = next((c for c in candidates if c), None) or _git("rev-parse", "HEAD")
    if not ref:
        msg = "builder_link: a link needs a git checkout (`git rev-parse HEAD` failed)"
        raise SystemExit(msg)
    return ref


def builder_url(page: Path, policy_dir: Path, version: str, *, keep_pinned: bool) -> str:
    """The builder link of one policy page."""
    sha256 = compute_pack_hash(policy_dir)
    ref = catalog_ref(page, policy_dir, version, sha256, keep_pinned=keep_pinned)
    return f"{BUILDER}#s={selection_code(policy_dir.name, version, sha256, ref)}"


def ref_holds_pack(ref: str, policy_dir: Path, sha256: str) -> bool:
    """True when the folder at `ref` hashes to `sha256`."""
    rel = policy_dir.relative_to(ROOT).as_posix()
    try:
        done = subprocess.run(
            ["git", "archive", "--format=tar", ref, "--", rel], cwd=ROOT, capture_output=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    with tempfile.TemporaryDirectory(prefix="policy-ref-") as tmp:
        with tarfile.open(fileobj=io.BytesIO(done.stdout)) as tar:
            tar.extractall(tmp, filter="data")
        return compute_pack_hash(Path(tmp) / rel) == sha256


def check_refs() -> int:
    """List every page whose builder link pins a ref that does not hold its sha256."""
    bad = []
    for policy_dir in policy_dirs():
        page = DOCS / policy_dir.name / "README.md"
        match = LINK_RE.search(page.read_text(encoding="utf-8")) if page.exists() else None
        entry = decode_code(match.group(1)) if match else None
        if not entry or not ref_holds_pack(entry["catalog"]["ref"], policy_dir, entry["policies"][0]["sha256"]):
            bad.append(page.relative_to(ROOT).as_posix())
    if bad:
        print("Builder links whose ref does not hold the page's pack (regenerate at the release):")
        print("\n".join(f"  {b}" for b in bad))
        return 1
    print("Every builder link's ref holds its pack.")
    return 0


if __name__ == "__main__":
    sys.exit(check_refs())
