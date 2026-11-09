"""Every published manifest's changelog runs one way by version: all oldest-first or all newest-first (IR-F46)."""

from __future__ import annotations

from itertools import pairwise

import pytest
import yaml
from trees import ROOT, policy_dirs

#: Two entries that share a version and differ in text; both stay, side by side (IR-F46).
SHARED_VERSION = {"verify-dependency-exists": "0.0.2", "injection-defense": "0.0.2"}

#: Mixed, and left alone while IR-F64 edits it; must still be mixed, so the entry is dropped when it is fixed.
PENDING = {"protect-agent-config"}

MANIFESTS = [d / "manifest.yaml" for d in policy_dirs() if (d / "manifest.yaml").is_file()]


def versions(path) -> list[tuple[int, ...]]:
    """The changelog's versions in file order, as integer tuples."""
    entries = yaml.safe_load(path.read_text(encoding="utf-8")).get("changelog") or []
    return [tuple(int(part) for part in str(entry["version"]).split(".")) for entry in entries]


def one_direction(vs: list[tuple[int, ...]]) -> bool:
    """True when the versions only rise or only fall; equal neighbours are judged separately."""
    steps = [b > a for a, b in pairwise(vs) if a != b]
    return all(steps) or not any(steps)


def test_the_check_sees_every_published_manifest():
    assert len(MANIFESTS) >= 70, f"only {len(MANIFESTS)} manifests found under {ROOT}"


@pytest.mark.parametrize("path", MANIFESTS, ids=lambda p: p.parent.name)
def test_changelog_runs_one_way_by_version(path):
    vs = versions(path)
    if path.parent.name in PENDING:
        assert not one_direction(vs), f"{path.parent.name} is ordered now: remove it from PENDING"
        return
    assert one_direction(vs), f"{path.relative_to(ROOT)}: changelog versions {vs} rise and fall"


@pytest.mark.parametrize("path", MANIFESTS, ids=lambda p: p.parent.name)
def test_a_version_appears_once_unless_named(path):
    vs = versions(path)
    shared = {v for v in vs if vs.count(v) > 1}
    named = SHARED_VERSION.get(path.parent.name)
    expected = {tuple(int(p) for p in named.split("."))} if named else set()
    assert shared == expected, f"{path.relative_to(ROOT)}: repeated versions {sorted(shared)}"
    for v in shared:
        at = [i for i, x in enumerate(vs) if x == v]
        assert at == list(range(at[0], at[0] + len(at))), f"{path.relative_to(ROOT)}: {v} entries are not adjacent"
