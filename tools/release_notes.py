#!/usr/bin/env python3
"""Print a release's notes: each policy's changelog entries added since the last catalog tag.

    python tools/release_notes.py --version 1.2.0 --since v1.1.0   # entries absent from v1.1.0's manifests
    python tools/release_notes.py --version 0.1.0                  # no tag yet: every entry

A policy new since the tag lists all its entries. Reads the working tree and `git show`; no network.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

import yaml
from trees import ROOT, policy_dirs

SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
#: A tag name that git cannot read as an option.
TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")


def entries(manifest: dict | None) -> list[dict]:
    """A manifest's changelog entries; none for a missing manifest or an empty changelog."""
    return list((manifest or {}).get("changelog") or [])


def manifest_at(root: Path, tag: str, policy_dir: Path) -> dict | None:
    """The policy's manifest as of `tag`, or None when the policy did not exist then."""
    rel = (policy_dir / "manifest.yaml").relative_to(root).as_posix()
    shown = subprocess.run(
        ["git", "-C", str(root), "show", f"{tag}:{rel}"], capture_output=True, text=True, check=False
    )
    return yaml.safe_load(shown.stdout) if shown.returncode == 0 else None


def new_entries(root: Path, policy_dir: Path, since: str | None) -> tuple[str, list[dict]]:
    """The policy's id and its changelog entries whose version the tagged manifest lacks."""
    manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8"))
    current = entries(manifest)
    if since is None:
        return manifest["id"], current
    old = {str(entry["version"]) for entry in entries(manifest_at(root, since, policy_dir))}
    return manifest["id"], [entry for entry in current if str(entry["version"]) not in old]


def render(root: Path, version: str, since: str | None) -> str:
    """The notes as markdown: one section per changed policy, one bullet per change."""
    if not SEMVER.fullmatch(version):
        msg = f"version must be MAJOR.MINOR.PATCH, got {version!r}"
        raise ValueError(msg)
    if since is not None:
        if not TAG.fullmatch(since):
            msg = f"unknown tag {since!r}"
            raise ValueError(msg)
        known = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", f"{since}^{{commit}}"],
            capture_output=True,
            check=False,
        )
        if known.returncode:
            msg = f"unknown tag {since!r}"
            raise ValueError(msg)
    lines = [f"# Chock catalog v{version}", ""]
    header = len(lines)
    for policy_dir in policy_dirs(root):
        policy_id, new = new_entries(root, policy_dir, since)
        if not new:
            continue
        lines += [f"## {policy_id}", ""]
        lines += [f"- {entry['version']} ({entry['date']}): {change}" for entry in new for change in entry["changes"]]
        lines.append("")
    if len(lines) == header:
        lines += [f"No policy changelog entries since {since}.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="the catalog version, MAJOR.MINOR.PATCH")
    parser.add_argument("--since", help="the last catalog tag; omit for the first release")
    args = parser.parse_args(argv)
    try:
        notes = render(ROOT, args.version, args.since)
    except ValueError as err:
        parser.error(str(err))
    else:
        print(notes, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
