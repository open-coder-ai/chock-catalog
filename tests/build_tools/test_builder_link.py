"""Each policy page carries one chock.sh builder link whose code is that policy's schema-2 selection."""

from __future__ import annotations

import gen_policy_docs
import pytest
from chock.install import selection
from chock.lock import compute_pack_hash
from trees import policy_dirs

LINK = gen_policy_docs.LINK_RE


@pytest.fixture(scope="module")
def pages():
    return {path.parent.name: text for path, text in gen_policy_docs.build().items()}


def test_every_page_has_one_link(pages):
    assert pages
    assert {pid: len(LINK.findall(text)) for pid, text in pages.items()} == dict.fromkeys(pages, 1)


def test_link_loads_to_the_policy_id(pages):
    link = LINK.search(pages["block-destructive-commands"]).group(0)
    loaded = selection.load(link)
    assert [p["id"] for p in loaded["policies"]] == ["block-destructive-commands"]
    assert loaded["client"] == "claude-code"


def test_code_pins_the_pack_hash_of_its_folder(pages):
    for policy_dir in policy_dirs():
        entry = gen_policy_docs.decode_code(LINK.search(pages[policy_dir.name]).group(1))["policies"][0]
        assert entry["id"] == policy_dir.name
        assert entry["sha256"] == compute_pack_hash(policy_dir)
