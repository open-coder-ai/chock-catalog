"""Each policy page carries one chock.sh builder link whose code is that policy's schema-2 selection."""

from __future__ import annotations

import subprocess

import builder_link
import gen_policy_docs
import pytest
from chock.install import selection
from chock.lock import compute_pack_hash
from chock.scaffold.new import render_kind
from trees import policy_dirs

LINK = builder_link.LINK_RE


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
        entry = builder_link.decode_code(LINK.search(pages[policy_dir.name]).group(1))["policies"][0]
        assert entry["id"] == policy_dir.name
        assert entry["sha256"] == compute_pack_hash(policy_dir)


def test_ref_is_a_commit_that_holds_the_pack(pages):
    policy_dir = policy_dirs()[0]
    code = LINK.search(pages[policy_dir.name]).group(1)
    pinned = builder_link.decode_code(code)
    assert len(pinned["catalog"]["ref"]) == 40
    assert builder_link.ref_holds_pack(pinned["catalog"]["ref"], policy_dir, pinned["policies"][0]["sha256"])


def test_a_ref_without_the_pack_is_flagged():
    policy_dir = policy_dirs()[0]
    assert not builder_link.ref_holds_pack("0" * 40, policy_dir, compute_pack_hash(policy_dir))
    assert not builder_link.ref_holds_pack("HEAD", policy_dir, "0" * 64)


def _git(root, *args):
    cmd = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args]
    return subprocess.run(cmd, cwd=root, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    monkeypatch.setattr(builder_link, "ROOT", tmp_path)
    monkeypatch.setattr(builder_link, "DOCS", tmp_path / "docs")
    return tmp_path


def _scaffold(root, policy_id="block-marker"):
    """The files `chock new policy <id> --kind content_regex` renders, in base/<id>."""
    for rel, text in render_kind("content_regex", policy_id, "2026-10-22").items():
        dest = root / "base" / policy_id / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8", newline="\n")
    return root / "base" / policy_id


def _page(root, policy_dir, ref):
    page = root / "docs" / policy_dir.name / "README.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    code = builder_link.selection_code(policy_dir.name, "0.0.1", compute_pack_hash(policy_dir), ref)
    page.write_text(f"[link]({builder_link.BUILDER}#s={code})\n", encoding="utf-8")
    return page


def _ref(page, policy_dir, *, keep_pinned):
    return builder_link.catalog_ref(page, policy_dir, "0.0.1", compute_pack_hash(policy_dir), keep_pinned=keep_pinned)


def test_a_regeneration_keeps_a_pin_that_holds_the_pack(repo):
    policy_dir = _scaffold(repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add")
    pin = _git(repo, "rev-parse", "HEAD")
    manifest = policy_dir / "manifest.yaml"
    original = manifest.read_text(encoding="utf-8")
    manifest.write_text(original + "# edit\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "edit")
    manifest.write_text(original, encoding="utf-8")
    _git(repo, "commit", "-qam", "revert")
    page = _page(repo, policy_dir, pin)
    assert _git(repo, "log", "-1", "--format=%H", "--", "base/block-marker") != pin
    assert _ref(page, policy_dir, keep_pinned=False) == pin


def test_a_pin_that_lacks_the_pack_moves_to_the_folders_commit(repo):
    (repo / "seed").write_text("x", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "seed")
    stale = _git(repo, "rev-parse", "HEAD")
    policy_dir = _scaffold(repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add")
    page = _page(repo, policy_dir, stale)
    assert _ref(page, policy_dir, keep_pinned=False) == _git(repo, "rev-parse", "HEAD")
    assert _ref(page, policy_dir, keep_pinned=True) == stale


def test_a_scaffolded_policy_holds_its_pack_once_committed(repo):
    policy_dir = _scaffold(repo)
    sha256 = compute_pack_hash(policy_dir)
    (repo / "seed").write_text("x", encoding="utf-8")
    _git(repo, "add", "seed")
    _git(repo, "commit", "-qm", "seed")
    head = _git(repo, "rev-parse", "HEAD")
    page = repo / "docs" / "block-marker" / "README.md"
    assert _ref(page, policy_dir, keep_pinned=False) == head
    assert not builder_link.ref_holds_pack(head, policy_dir, sha256), "an uncommitted pack is in no commit"
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add block-marker")
    ref = _ref(page, policy_dir, keep_pinned=False)
    assert ref == _git(repo, "rev-parse", "HEAD")
    assert builder_link.ref_holds_pack(ref, policy_dir, sha256)


def test_no_page_quotes_the_selection_code(pages):
    quoted = [pid for pid, text in pages.items() if "--selection '" in text or '--selection "' in text]
    assert quoted == []
    assert all("--selection <code> --apply" in text for text in pages.values())
