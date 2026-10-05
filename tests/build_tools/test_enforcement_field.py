"""The manifest's `enforcement` is shown as a tier; what a policy does comes from the derived label."""

from __future__ import annotations

import importlib
import sys
import types

import gen_policy_docs
import pytest
import yaml
from trees import ROOT

REGISTRY = ROOT / "registry.yaml"
ROWS = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["policies"]


@pytest.fixture(scope="module")
def pages():
    return {path.parent.name: text for path, text in gen_policy_docs.build().items()}


@pytest.fixture
def brand(monkeypatch):
    """The card module, with cairosvg (the renderer, not in the test requirements) stubbed: only its lists are read."""
    monkeypatch.syspath_prepend(str(ROOT / "docs" / "assets"))
    monkeypatch.setitem(sys.modules, "cairosvg", types.ModuleType("cairosvg"))
    monkeypatch.delitem(sys.modules, "gen_brand_assets", raising=False)
    monkeypatch.delitem(sys.modules, "brandkit", raising=False)
    return importlib.import_module("gen_brand_assets")


def test_blocking_is_every_policy_labelled_block_on_claude_code(brand):
    expected = [r["id"] for r in ROWS if r["label"]["claude-code"]["keyword"] == "block"]
    assert expected, "no policy is labelled block: the test would pass on an empty list"
    assert expected == brand.BLOCKING


@pytest.mark.parametrize(
    ("policy_id", "word", "tier"),
    [("block-no-verify", "blocks", "advise"), ("scan-secrets-entropy", "asks", "block")],
)
def test_policy_page_shows_the_label_and_the_manifest_tier(pages, policy_id, word, tier):
    page = pages[policy_id]
    assert f"**On Claude Code** | {word}" in page
    assert f"**Manifest tier** | `enforcement: {tier}`" in page
    assert "(`enforcement:" not in page.split("**Type**", 1)[1].splitlines()[0]


def test_every_label_keyword_has_a_page_word():
    assert {r["label"]["claude-code"]["keyword"] for r in ROWS} <= set(gen_policy_docs.LABEL_WORD)


def test_registry_header_explains_both_fields():
    header = REGISTRY.read_text(encoding="utf-8").split("\npolicies:", 1)[0]
    assert (
        "# label: what the policy does on each agent, derived from the hooks it ships "
        "(tools/gen_registry.py). Read this, not enforcement."
    ) in header
    assert (
        "# enforcement: the manifest's tier (propagation default and index ranking); "
        "it does not say what the policy blocks."
    ) in header
