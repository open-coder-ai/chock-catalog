"""opaque-blob-guard: signatures, scope, entropy and the read bounds."""

from __future__ import annotations

import bz2
import gzip
import lzma
import random
from pathlib import Path

import pytest
from policies import blobkit

gate, ns = blobkit.load()
PAD = b"\0" * 24
RANDOM = random.Random(7).randbytes  # noqa: S311 -- a fixed seed: test data, never a secret
SIGNATURES = {
    "zip": b"PK\x03\x04" + PAD,
    "zip-empty": b"PK\x05\x06" + PAD,
    "zip-spanned": b"PK\x07\x08" + PAD,
    "gzip": gzip.compress(b"hello hello hello"),
    "xz": lzma.compress(b"hello hello hello"),
    "bzip2": bz2.compress(b"hello hello hello"),
    "7z": b"7z\xbc\xaf\x27\x1c" + PAD,
    "zstd": b"\x28\xb5\x2f\xfd" + PAD,
    "rar": b"Rar!\x1a\x07\x00" + PAD,
    "tar": b"\0" * 257 + b"ustar\0" + PAD,
    "elf": b"\x7fELF\x02\x01\x01" + PAD,
    "macho-32": b"\xfe\xed\xfa\xce" + PAD,
    "macho-64": b"\xfe\xed\xfa\xcf" + PAD,
    "macho-32-le": b"\xce\xfa\xed\xfe" + PAD,
    "macho-64-le": b"\xcf\xfa\xed\xfe" + PAD,
    "cafebabe": b"\xca\xfe\xba\xbe\0\0\0\x34" + PAD,
    "pe": b"MZ\x90\x00\x03\x00" + PAD,
    "wasm": b"\0asm\x01\0\0\0" + PAD,
    "lz4": b"\x04\x22\x4d\x18" + PAD,
    "compress": b"\x1f\x9d\x90" + PAD,
    "lzip": b"LZIP\x01" + PAD,
    "ar": b"!<arch>\n" + PAD,
    "rpm": b"\xed\xab\xee\xdb" + PAD,
    "cab": b"MSCF" + PAD,
    "ole2": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + PAD,
    "sqlite": b"SQLite format 3\0" + PAD,
}


def check(tmp_path: Path, files: dict[str, str | bytes], **kw: object) -> list[tuple[str, str]]:
    repo = blobkit.make_repo(tmp_path, files)
    return blobkit.rules(blobkit.run(gate, repo, files, **kw))  # type: ignore[arg-type]


def test_every_signature_in_the_table_is_exercised() -> None:
    assert {sig.name for sig in ns.tables.load().magic} == set(SIGNATURES)


@pytest.mark.parametrize("name", sorted(SIGNATURES))
def test_signature_is_found_whatever_the_extension(tmp_path: Path, name: str) -> None:
    assert check(tmp_path, {"testdata/notes.txt": SIGNATURES[name]}) == [("testdata/notes.txt", "opaque-magic")]


def test_cafebabe_is_labelled_by_extension(tmp_path: Path) -> None:
    files = {"tests/A.class": SIGNATURES["cafebabe"], "tests/lib.dylib": SIGNATURES["cafebabe"]}
    repo = blobkit.make_repo(tmp_path, files)
    labels = {f["path"]: f["message"] for f in blobkit.run(gate, repo, files)}
    assert labels["tests/A.class"].startswith("Java class file")
    assert labels["tests/lib.dylib"].startswith("Java class or universal Mach-O")


@pytest.mark.parametrize("text", ["MZ-1234 is a ticket id\n", "MZ Industries \u2014 notes\n"])
def test_a_text_file_that_only_starts_with_mz_is_not_a_pe(tmp_path: Path, text: str) -> None:
    assert check(tmp_path, {"tests/a.txt": text}) == []


@pytest.mark.parametrize(
    "path",
    ["tests/a.xz", "Tests/a.xz", "__tests__/a.xz", "e2e/a.xz", "third_party/a.xz", "test/a.xz", "fixtures/a.xz", "testdata/a.xz", "spec/a.xz", "m4/a.xz", "vendor/a.xz",
     "pkg/sub/tests/deep/a.xz", "gradle/wrapper/a.xz", "app/gradle/wrapper/a.xz"],
)  # fmt: skip
def test_scoped_folders_at_any_depth(tmp_path: Path, path: str) -> None:
    assert check(tmp_path, {path: SIGNATURES["xz"]}) == [(path, "opaque-magic")]


@pytest.mark.parametrize("path", ["src/a.xz", "tests.xz", "docs/gradle/a.xz", "gradle/a.xz", "TESTS/a.xz"])
def test_the_same_bytes_elsewhere_are_not_judged(tmp_path: Path, path: str) -> None:
    assert check(tmp_path, {path: SIGNATURES["xz"]}) == []


def test_plain_text_in_a_scoped_folder_is_allowed(tmp_path: Path) -> None:
    assert check(tmp_path, {"tests/a.txt": "assert 1 == 1\n" * 20000}) == []


def test_high_entropy_over_the_floor_asks(tmp_path: Path) -> None:
    assert check(tmp_path, {"fixtures/blob.dat": RANDOM(150_000)}) == [("fixtures/blob.dat", "high-entropy")]


def test_high_entropy_under_the_floor_is_allowed(tmp_path: Path) -> None:
    assert check(tmp_path, {"fixtures/blob.dat": RANDOM(100_000)}) == []


def test_random_data_behind_a_text_lead_in_is_still_found(tmp_path: Path) -> None:
    lead = b"# header\n" * 20000
    assert check(tmp_path, {"fixtures/blob.dat": lead + RANDOM(150_000)}) == [("fixtures/blob.dat", "high-entropy")]


def test_a_short_random_tail_is_not_a_window(tmp_path: Path) -> None:
    assert check(tmp_path, {"fixtures/blob.dat": b"a" * 16384 * 7 + RANDOM(100)}) == []


@pytest.mark.parametrize(
    "head",
    [
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff\xe0",
        b"GIF87a",
        b"GIF89a",
        b"RIFF\0\0\0\0WEBP",
        b"%PDF-1.7\n",
        b"wOF2",
        b"wOFF",
        b"OggS",
        b"ID3\x04",
        b"\0\0\0\x18ftypmp42",
        b"\x1a\x45\xdf\xa3",
        b"\0\0\x01\0",
        b"II*\0",
        b"MM\0*",
        b"\0\x01\0\0\0",
        b"OTTO",
    ],
    ids=[
        "png",
        "jpeg",
        "gif87",
        "gif89",
        "webp",
        "pdf",
        "woff2",
        "woff",
        "ogg",
        "mp3",
        "mp4",
        "mkv",
        "ico",
        "tiff-le",
        "tiff-be",
        "ttf",
        "otf",
    ],
)
def test_media_is_exempt_from_the_entropy_rule_only(tmp_path: Path, head: bytes) -> None:
    assert check(tmp_path, {"fixtures/pic.bin": head + RANDOM(150_000)}) == []


def test_a_media_name_exempts_nothing(tmp_path: Path) -> None:
    found = check(tmp_path, {"fixtures/pic.png": b"PK\x03\x04" + RANDOM(150_000)})
    assert found == [("fixtures/pic.png", "opaque-magic"), ("fixtures/pic.png", "high-entropy")]


def test_a_file_over_the_read_cap_is_judged_on_its_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ns.source, "HEAD_CAP", 4096)
    monkeypatch.setattr(ns.source, "HASH_CAP", 20_000)
    repo = blobkit.make_repo(tmp_path, {"testdata/big.txt": SIGNATURES["xz"] + b"\0" * 60_000})
    (found,) = blobkit.run(gate, repo, ["testdata/big.txt"])
    assert found["rule"] == "opaque-magic"
    assert found["key"].startswith("opaque-magic|xz stream")  # unhashed: keyed by its reason, never allowlistable


def test_a_big_file_never_reads_past_the_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ns.source, "HEAD_CAP", 4096)
    monkeypatch.setattr(ns.source, "HASH_CAP", 20_000)
    big = tmp_path / "big"
    big.write_bytes(b"\0" * 70_000)
    blob = ns.source.read_disk(str(tmp_path), "big")
    assert (len(blob.head), blob.size, blob.sha) == (4096, 70_000, None)


def test_the_head_alone_is_hashed_when_the_file_is_small(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"abc")
    blob = ns.source.read_disk(str(tmp_path), "f")
    assert (blob.head, blob.size) == (b"abc", 3)
    assert blob.sha == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
