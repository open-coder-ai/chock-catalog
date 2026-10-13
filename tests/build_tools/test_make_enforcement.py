"""docs/figures/make_enforcement.py: an `enforces` word no tier names stops the render."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

FIGURES = Path(__file__).resolve().parents[2] / "docs" / "figures"


@pytest.fixture
def make_enforcement(monkeypatch):
    monkeypatch.syspath_prepend(str(FIGURES))
    return importlib.import_module("make_enforcement")


def test_every_tier_counts_only_its_own_words(make_enforcement, tmp_path: Path, monkeypatch) -> None:
    registry = tmp_path / "registry.yaml"
    registry.write_text(
        "policies:\n"
        "- id: a\n  enforces: enforced-at-commit\n"
        "- id: b\n  enforces: best-effort (pre-tool-use)\n"
        "- id: c\n  enforces: advisory\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(make_enforcement, "REGISTRY", registry)
    assert [n for n, _, _ in make_enforcement.read_counts()] == [1, 1, 1]


def test_an_unknown_grade_word_names_the_word_and_the_file(make_enforcement, tmp_path: Path, monkeypatch) -> None:
    registry = tmp_path / "registry.yaml"
    registry.write_text(
        "policies:\n- id: a\n  enforces: advisory\n- id: b\n  enforces: aspirational\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(make_enforcement, "REGISTRY", registry)
    with pytest.raises(SystemExit) as stopped:
        make_enforcement.read_counts()
    assert "'aspirational'" in str(stopped.value)
    assert str(registry) in str(stopped.value)
    assert "id: b" in str(stopped.value)
