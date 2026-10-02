"""chock_scan.safe_read: the bounded, explicit file reader script gates share.

Run against lib/ and every copy a policy ships. Property cases draw from a seeded generator
(hypothesis is not a dev dependency here), so a failure reproduces from its seed.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import random
import sys
from pathlib import Path
from types import ModuleType

import pytest
from trees import ROOT, TREES

SOURCES = sorted(
    {ROOT / "lib" / "chock_scan"}
    | {p.parent for tree in TREES for p in (ROOT / tree).glob("*/implementations/chock_scan/safe_read.py")}
)
SEEDS = range(40)
BOM = "﻿"


def _load(package: Path) -> ModuleType:
    name = "safe_read_" + package.relative_to(ROOT).as_posix().replace("/", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, package / "safe_read.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=SOURCES, ids=[s.relative_to(ROOT).as_posix() for s in SOURCES])
def sr(request: pytest.FixtureRequest) -> ModuleType:
    return _load(request.param)


def _text(rng: random.Random, size: int) -> str:
    """Any Unicode scalar values except NUL, weighted towards the characters config files hold."""
    pools = [
        lambda: rng.choice("abc xyz:-#'\"\n\r\t{}[],=\\"),
        lambda: chr(rng.randrange(0x80, 0x800)),
        lambda: chr(rng.choice([rng.randrange(0x800, 0xD800), rng.randrange(0xE000, 0x10000)])),
        lambda: chr(rng.randrange(0x10000, 0x110000)),
        lambda: BOM,
    ]
    return "".join(rng.choice(pools)() for _ in range(size)).replace("\0", "")


@pytest.mark.parametrize("seed", SEEDS)
def test_decode_round_trips_any_text_and_drops_one_leading_bom(sr: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    text = _text(rng, rng.randrange(0, 200))
    assert sr.decode(text.encode("utf-8")) == text.removeprefix(BOM)
    assert sr.decode((BOM + text).encode("utf-8")) == text


@pytest.mark.parametrize("seed", SEEDS)
def test_decode_never_raises_anything_but_unreadable_on_arbitrary_bytes(sr: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    data = rng.randbytes(rng.randrange(0, 64))
    try:
        text = sr.decode(data)
    except sr.UnreadableError:
        assert b"\0" in data or not _is_utf8(data)
    else:
        assert text.encode("utf-8") in (data, data.removeprefix(BOM.encode("utf-8")))


@pytest.mark.parametrize("seed", SEEDS)
def test_a_nul_anywhere_is_binary(sr: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    data = bytearray(_text(rng, rng.randrange(0, 50)).encode("utf-8"))
    at = rng.randrange(0, len(data) + 1)
    data[at:at] = b"\0"
    with pytest.raises(sr.UnreadableError, match=rf"binary \(NUL byte at {bytes(data).index(0)}\)"):
        sr.decode(bytes(data))


@pytest.mark.parametrize(
    "data",
    [b"\xff", b"\xc3", b"ok\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xc0\xaf", "é".encode("latin-1")],
    ids=["ff", "truncated", "continuation", "surrogate", "above-max", "overlong", "latin-1"],
)
def test_invalid_utf8_is_refused_by_name_and_offset(sr: ModuleType, data: bytes) -> None:
    with pytest.raises(sr.UnreadableError, match=r"^cfg\.yml: not UTF-8 \(byte \d+\)$"):
        sr.decode(data, "cfg.yml")


@pytest.mark.parametrize("seed", SEEDS)
def test_read_text_is_decode_of_the_file_bytes(sr: ModuleType, seed: int, tmp_path: Path) -> None:
    rng = _rng(seed)
    data = _text(rng, rng.randrange(0, 300)).encode("utf-8")
    path = tmp_path / "f.yml"
    path.write_bytes(data)
    assert sr.read_text(path) == sr.decode(data)
    assert sr.read_text(str(path), limit=len(data)) == sr.decode(data)


def test_the_limit_is_inclusive_and_one_byte_over_is_refused(sr: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b"x" * 10)
    assert sr.read_text(path, limit=10) == "x" * 10
    with pytest.raises(sr.UnreadableError, match="larger than 9 bytes"):
        sr.read_text(path, limit=9)
    path.write_bytes(b"")
    assert sr.read_text(path, limit=0) == ""
    for bad in (-1, sr.MAX_LIMIT + 1, sys.maxsize):
        with pytest.raises(ValueError, match="limit must be 0"):
            sr.read_text(path, limit=bad)
    assert sr.LIMIT == 1 << 20
    path.write_bytes(b"y" * (sr.CHUNK * 3 + 5))
    assert sr.read_text(path, limit=sr.CHUNK * 3 + 5) == "y" * (sr.CHUNK * 3 + 5)
    with pytest.raises(sr.UnreadableError, match="larger than"):
        sr.read_text(path, limit=sr.CHUNK * 2)


def test_the_default_limit_refuses_a_file_over_one_mebibyte(sr: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "huge.txt"
    path.write_bytes(b"a" * (sr.LIMIT + 1))
    with pytest.raises(sr.UnreadableError, match="larger than 1048576 bytes"):
        sr.read_text(path)


def test_a_missing_file_or_a_folder_is_unreadable(sr: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(sr.UnreadableError, match="No such file or directory"):
        sr.read_text(tmp_path / "absent")
    with pytest.raises(sr.UnreadableError, match="not a regular file"):
        sr.read_text(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_a_fifo_is_refused_without_blocking(sr: ModuleType, tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(sr.UnreadableError, match="not a regular file"):
        sr.read_text(fifo)


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="no /dev/zero on this platform")
def test_an_endless_device_is_refused_not_read(sr: ModuleType) -> None:
    with pytest.raises(sr.UnreadableError, match="not a regular file"):
        sr.read_text("/dev/zero")


@pytest.mark.skipif(not Path("/proc/self/mem").exists(), reason="no procfs on this platform")
def test_a_read_error_is_unreadable_and_closes_the_file(sr: ModuleType) -> None:
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(sr.UnreadableError, match="/proc/self/mem: "):
        sr.read_text("/proc/self/mem")
    assert len(os.listdir("/proc/self/fd")) == before


def test_a_failing_fstat_is_unreadable(sr: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "f").write_text("x", encoding="utf-8")
    closed: list[int] = []
    real_close = os.close

    def fstat(_fd: int) -> os.stat_result:
        raise OSError(5, "Input/output error")

    def close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(sr.os, "fstat", fstat)
    monkeypatch.setattr(sr.os, "close", close)
    with pytest.raises(sr.UnreadableError, match="Input/output error"):
        sr.read_text(tmp_path / "f")
    assert len(closed) == 1


def test_a_symlink_to_a_regular_file_is_read(sr: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "real.toml").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "link.toml").symlink_to(tmp_path / "real.toml")
    assert sr.read_text(tmp_path / "link.toml") == "a = 1\n"


def test_a_binary_file_is_refused_with_its_name(sr: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "x.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00")
    with pytest.raises(sr.UnreadableError, match=r"x\.bin: binary \(NUL byte at 7\)$"):
        sr.read_text(path)


def test_newlines_are_kept_as_written(sr: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "crlf.ini"
    path.write_bytes(b"a=1\r\nb=2\rc=3\n")
    assert sr.read_text(path) == "a=1\r\nb=2\rc=3\n"


def test_the_package_init_imports_nothing() -> None:
    """A policy ships only the modules it lists, so the package must not import any of them."""
    for package in SOURCES:
        tree = compile((package / "__init__.py").read_text(encoding="utf-8"), "__init__.py", "exec")
        assert tree.co_names == ("__doc__",), package


def test_the_module_is_stdlib_only() -> None:
    tree = ast.parse((ROOT / "lib" / "chock_scan" / "safe_read.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names
    assert {n.split(".")[0] for n in names} <= set(sys.stdlib_module_names)


def _rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret


def _is_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True
