"""opaque-blob-guard: reading the working tree works where os.O_NOFOLLOW does not exist (Windows) and still refuses a link."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policies import blobkit

gate, ns = blobkit.load()


@pytest.fixture
def _no_nofollow(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Remove os.O_NOFOLLOW and record the flags of every open."""
    nofollow = os.O_NOFOLLOW
    monkeypatch.delattr(os, "O_NOFOLLOW")
    flags: list[int] = []
    real = os.open

    def spy(path: str, mode: int, *args: int, **kwargs: int) -> int:
        flags.append(mode)
        assert not mode & nofollow
        return real(path, mode, *args, **kwargs)

    monkeypatch.setattr(ns.source.os, "open", spy)
    return flags


@pytest.mark.usefixtures("_no_nofollow")
def test_a_regular_file_is_read_without_o_nofollow(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"abc")
    blob = ns.source.read_disk(str(tmp_path), "a.bin")
    assert blob is not None
    assert blob.head == b"abc"


@pytest.mark.usefixtures("_no_nofollow")
def test_a_symlink_out_of_the_repository_is_refused_before_any_open(tmp_path: Path, _no_nofollow: list[int]) -> None:
    repo, outside = tmp_path / "repo", tmp_path / "outside.bin"
    repo.mkdir()
    outside.write_bytes(b"secret")
    (repo / "link.bin").symlink_to(outside)
    with pytest.raises(ns.source.Link):
        ns.source.read_disk(str(repo), "link.bin")
    assert _no_nofollow == []


@pytest.mark.usefixtures("_no_nofollow")
def test_a_symlink_inside_the_repository_is_not_read(tmp_path: Path, _no_nofollow: list[int]) -> None:
    (tmp_path / "real.bin").write_bytes(b"abc")
    (tmp_path / "link.bin").symlink_to(tmp_path / "real.bin")
    assert ns.source.read_disk(str(tmp_path), "link.bin") is None
    assert _no_nofollow == []
