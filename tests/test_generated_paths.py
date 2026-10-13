"""Generated output carries no build-machine path: a home directory leaks the builder's user name."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# measurements/context-report/: written by dogfood.py (*.resolved.json, pre-generated-scripts.json)
# and inventory.py (inventory.json). Docs, registry.yaml and lib/ copies render manifests and evals
# that name such paths on purpose, so they stay out.
GENERATED = ("measurements",)
# The generators themselves may name a path to scrub it.
SOURCE_SUFFIXES = {".py"}
BUILD_PATH = re.compile(r"(?<![\w.~-])(?:/home/[\w.-]+|/root/|/Users/[\w.-]+|[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/))")


def generated_files() -> list[str]:
    paths = (p for top in GENERATED for p in sorted((ROOT / top).rglob("*")))
    return [
        p.relative_to(ROOT).as_posix()
        for p in paths
        if p.is_file() and p.suffix not in SOURCE_SUFFIXES and "__pycache__" not in p.parts
    ]


def test_the_pattern_catches_each_build_machine_form() -> None:
    samples = ["/home/alice/x", "/root/.cache", "/Users/bob/x", "C:\\Users\\bob", '"C:\\\\Users\\\\bob"', "c:/Users/b"]
    clean = ["<bundle-root>/x", "https://example.com/home/x", "src/root/x", "/usr/home"]
    assert [s for s in samples if not BUILD_PATH.search(s)] == []
    assert [s for s in clean if BUILD_PATH.search(s)] == []


def test_generated_output_holds_no_build_machine_path() -> None:
    files = generated_files()
    assert files, f"no tracked files under {GENERATED}: the scan would pass vacuously"
    hits = [
        f"{rel}:{n}: {m.group(0)}"
        for rel in files
        for n, line in enumerate((ROOT / rel).read_text(encoding="utf-8", errors="replace").splitlines(), 1)
        for m in [BUILD_PATH.search(line)]
        if m
    ]
    assert not hits, "Build-machine paths in generated output; scrub them in the generator:\n" + "\n".join(hits)
