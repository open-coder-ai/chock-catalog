"""tools/framework_ref.py: the base branch the adoption workflow may name, and the guard that refuses the rest."""

from __future__ import annotations

import framework_ref
import pytest
import yaml
from trees import ROOT


@pytest.mark.parametrize("base", ["main", "rel12-catalog", "rel1-catalog", "rel120-catalog"])
def test_an_allowed_base_branch_passes(monkeypatch: pytest.MonkeyPatch, base: str) -> None:
    monkeypatch.setenv("BASE_BRANCH", base)
    assert framework_ref.base_valid(base)
    assert framework_ref.main(["check-base"]) == 0


@pytest.mark.parametrize(
    "base",
    [
        "rel12-catalog; id",
        "refs/pull/1/head",
        "adopt/x",
        "",
        "Main",
        "main\n",
        "rel12-catalog\n",
        "main\nrel12-catalog",
        " main",
        "rel-catalog",
        "relx-catalog",
        "REL12-catalog",
        "$(id)",
        "rel12-catalog/../main",
    ],
)
def test_any_other_base_branch_is_refused_loudly(monkeypatch: pytest.MonkeyPatch, capsys, base: str) -> None:
    monkeypatch.setenv("BASE_BRANCH", base)
    assert not framework_ref.base_valid(base)
    assert framework_ref.main(["check-base"]) == framework_ref.REFUSED
    assert "::error::BASE_BRANCH must be exactly" in capsys.readouterr().err


def test_an_unset_base_branch_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BASE_BRANCH", raising=False)
    assert framework_ref.main(["check-base"]) == framework_ref.REFUSED


def _adopt_steps() -> list[dict]:
    workflow = yaml.safe_load((ROOT / ".github/workflows/adopt-framework.yml").read_text(encoding="utf-8"))
    return workflow["jobs"]["adopt"]["steps"]


def test_the_inline_base_guard_runs_before_any_checkout_with_the_same_pattern() -> None:
    steps = _adopt_steps()
    first_checkout = next(
        i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    guards = [i for i, step in enumerate(steps) if "BASE_BRANCH" in (step.get("env") or {}) and "run" in step]
    assert guards
    assert guards[0] < first_checkout
    guard = steps[guards[0]]
    assert guard["env"] == {"BASE_BRANCH": "${{ inputs.base_branch }}"}
    assert f"^({framework_ref.BASE.pattern})$" in guard["run"]
