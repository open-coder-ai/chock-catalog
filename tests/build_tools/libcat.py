"""A throwaway catalog for the lib/ copy tests: one lib package, two policies, one consuming it."""

from __future__ import annotations

from pathlib import Path

SHARED = {"__init__.py": '"""pkg."""\n', "a.py": "from .b import x\n", "b.py": "x = 1\n", "c.py": "y = 2\n"}


def make(root: Path) -> Path:
    for name, text in SHARED.items():
        put(root / "lib" / "pkg" / name, text)
    for pid in ("one", "two"):
        put(root / "base" / pid / "manifest.yaml", f"id: {pid}\n")
    declare(root, "base/one:\n  pkg: [a, b]\n")
    return root


def put(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def declare(root: Path, text: str) -> None:
    put(root / "lib" / "consumers.yaml", text)


def copy(root: Path, policy: str = "one") -> Path:
    return root / "base" / policy / "implementations" / "pkg"
