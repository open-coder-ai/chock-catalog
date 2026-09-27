#!/usr/bin/env python3
"""Fail when a policy this repo runs is ahead of, or has diverged from, the copy it publishes.

`.agents/policies/<id>/` is what governs this repository; `<tree>/<id>/` is what adopters get.
A fix made only in the installed copy ships to nobody -- pin-github-actions 0.0.3 lived there
alone for a week. Ahead, or different at the same version, fails. Behind is a warning: base/
moved first, and `chock add <id> --from . --force` catches this repo up.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from trees import ROOT, policy_dirs

INSTALLED = Path(".agents") / "policies"
IGNORED = {"__pycache__"}


def version(policy_dir: Path) -> tuple[int, ...]:
    raw = str(yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8"))["version"])
    return tuple(int(part) for part in raw.split("."))


def _files(folder: Path) -> dict[str, Path]:
    return {
        p.relative_to(folder).as_posix(): p
        for p in folder.rglob("*")
        if p.is_file() and not IGNORED & set(p.relative_to(folder).parts)
    }


def differs(left: Path, right: Path) -> list[str]:
    """Relative paths that are not byte-identical between two policy folders."""
    a, b = _files(left), _files(right)
    return sorted(
        rel for rel in a.keys() | b.keys() if rel not in a or rel not in b or a[rel].read_bytes() != b[rel].read_bytes()
    )


def compare(root: Path = ROOT) -> tuple[list[str], list[str]]:
    """(problems, warnings) for every installed policy that has a published source."""
    sources = {d.name: d for d in policy_dirs(root)}
    problems: list[str] = []
    warnings: list[str] = []
    for installed in sorted(p for p in (root / INSTALLED).iterdir() if (p / "manifest.yaml").is_file()):
        source = sources.get(installed.name)
        if source is None:
            continue  # governs this repo only; nothing published to drift from
        have, ships = version(installed), version(source)
        label = f"{installed.name}: installed {'.'.join(map(str, have))}, {source.parent.name}/ has "
        label += ".".join(map(str, ships))
        if have > ships:
            problems.append(f"{label} -- port the change into {source.relative_to(root).as_posix()}/")
        elif have < ships:
            warnings.append(f"{label} -- chock add {installed.name} --from . --force")
        elif changed := differs(installed, source):
            problems.append(f"{label}, but they differ at the same version: {', '.join(changed)}")
    return problems, warnings


def main(root: Path = ROOT) -> int:
    problems, warnings = compare(root)
    for line in warnings:
        print(f"warning: {line}")
    if problems:
        print("Installed policies are ahead of, or diverge from, what this catalog publishes:")
        print("\n".join(f"  {p}" for p in problems))
        return 1
    print(f"Every installed policy matches or trails its published source ({len(warnings)} behind).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
