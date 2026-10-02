"""chock_scan.sniff: bytes to text (BOMs, UTF-16/32 without one, binary, undecodable), the size cap, and shebangs."""

from __future__ import annotations

import codecs
import gzip
from types import ModuleType

import pytest

K8S = "apiVersion: v1\nkind: Pod\n"


@pytest.mark.parametrize(
    ("codec", "bom", "label"),
    [
        ("utf-8", codecs.BOM_UTF8, "utf-8-bom"),
        ("utf-16-le", codecs.BOM_UTF16_LE, "utf-16-le-bom"),
        ("utf-16-be", codecs.BOM_UTF16_BE, "utf-16-be-bom"),
        ("utf-32-le", codecs.BOM_UTF32_LE, "utf-32-le-bom"),
        ("utf-32-be", codecs.BOM_UTF32_BE, "utf-32-be-bom"),
        ("utf-16-le", b"", "utf-16-le"),
        ("utf-16-be", b"", "utf-16-be"),
        ("utf-32-le", b"", "utf-32-le"),
        ("utf-32-be", b"", "utf-32-be"),
    ],
)
def test_every_unicode_encoding_yaml_allows_is_read(sn: ModuleType, codec: str, bom: bytes, label: str) -> None:
    result = sn.sniff(bom + K8S.encode(codec))
    assert (result.content, result.encoding) == ("text", label)
    assert result.kinds("high") == {"kubernetes"}


def test_a_shebang_after_a_bom_still_names_its_interpreter(sn: ModuleType) -> None:
    result = sn.sniff(codecs.BOM_UTF8 + b"#!/bin/sh\necho\n")
    assert result.interpreter == ("sh",)
    assert result.kinds() == {"script", "shell"}


def test_a_nul_after_the_first_line_is_binary_but_the_script_is_still_seen(sn: ModuleType) -> None:
    """bash runs a file whose NUL comes after the first line; calling it only binary would hide it."""
    result = sn.sniff(b"#!/bin/bash\ncurl x | sh\n\0\0\0")
    assert result.content == "binary"
    assert result.kinds("high") == {"script", "shell"}
    assert not result.unknown


def test_invalid_utf8_is_undecodable_and_still_sniffed(sn: ModuleType) -> None:
    result = sn.sniff((K8S + "# caf").encode("utf-8") + b"\xe9\n")
    assert (result.content, result.encoding) == ("undecodable", "utf-8")
    assert result.kinds("high") == {"kubernetes"}


def test_a_utf16_guess_is_also_read_as_utf8(sn: ModuleType) -> None:
    """`#` then NUL looks like UTF-16-LE (and decodes as it); read as UTF-8 it is a Dockerfile."""
    result = sn.sniff(b"#\0\nFROM alpine\nRUN true\n")
    assert (result.content, result.encoding) == ("text", "utf-16-le")
    assert result.kinds("high") == {"dockerfile"}


def test_an_odd_length_utf16_file_is_undecodable(sn: ModuleType) -> None:
    result = sn.sniff(codecs.BOM_UTF16_LE + K8S.encode("utf-16-le") + b"x")
    assert result.content == "undecodable"
    assert result.kinds("high") == {"kubernetes"}


@pytest.mark.parametrize(
    "data",
    [
        gzip.compress(b"x" * 100, mtime=0),
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        b"PK\x03\x04\x14\x00\x00\x00",
        b"\x00\x00\x00\x00",
    ],
    ids=["gzip", "elf", "png", "zip", "nuls"],
)
def test_binary_formats_are_binary_and_unknown(sn: ModuleType, data: bytes) -> None:
    result = sn.sniff(data)
    assert result.content == "binary"
    assert result.candidates == ()
    assert result.unknown


def test_empty_and_short_input_is_unknown_text(sn: ModuleType) -> None:
    for data in (b"", b"a", b"ab", b"abc"):
        result = sn.sniff(data)
        assert (result.content, result.encoding, result.candidates, result.interpreter) == ("text", "utf-8", (), ())
        assert result.unknown


def test_over_the_limit_is_too_large_not_unknown(sn: ModuleType) -> None:
    data = K8S.encode("utf-8")
    assert sn.sniff(data, limit=len(data)).kinds() == {"kubernetes"}
    result = sn.sniff(data, limit=len(data) - 1)
    assert result == ("too-large", None, (), ())
    assert not result.unknown
    assert result.kinds() == frozenset()
    assert sn.sniff(b"x" * (sn.LIMIT + 1)).content == "too-large"
    assert sn.sniff(b"", limit=0).content == "text"


@pytest.mark.parametrize("bad", [-1, 1 << 27, 1.5, True, None, "10"])
def test_a_limit_outside_the_range_is_a_caller_error(sn: ModuleType, bad: object) -> None:
    with pytest.raises(ValueError, match="limit must be 0"):
        sn.sniff(b"x", limit=bad)


SHEBANGS = {
    "#!/bin/sh": ("sh",),
    "#! /bin/bash -e": ("bash", "-e"),
    "#!/usr/bin/env bash": ("bash",),
    "#!/usr/bin/env -S bash -eu": ("bash", "-eu"),
    "#!/usr/bin/env -Sbash -x": ("bash", "-x"),
    "#!/usr/bin/env -vS bash": ("bash",),
    "#!/usr/bin/env -S -i bash": ("bash",),
    "#!/usr/bin/env --split-string=zsh -f": ("zsh", "-f"),
    "#!/usr/bin/env --split-string zsh": ("zsh",),
    "#!/usr/bin/env -u HOME dash": ("dash",),
    "#!/usr/bin/env -uHOME dash": ("dash",),
    "#!/usr/bin/env -iuHOME dash": ("dash",),
    "#!/usr/bin/env --unset HOME ksh": ("ksh",),
    "#!/usr/bin/env --unset=HOME ksh": ("ksh",),
    "#!/usr/bin/env -C /tmp sh": ("sh",),
    "#!/usr/bin/env -P /bin sh": ("sh",),
    "#!/usr/bin/env --chdir /tmp sh": ("sh",),
    "#!/usr/bin/env -i - A=1 B=2 /bin/sh -x": ("sh", "-x"),
    "#!/usr/bin/env -- bash": ("bash",),
    "#!/usr/bin/env --ignore-environment bash": ("bash",),
    "#!/usr/bin/env": ("env",),
    "#!/usr/bin/env -i": ("env",),
    "#!/usr/bin/env -u": ("env",),
    "#!/usr/bin/env --unset": ("env",),
    "#!/usr/bin/env --": ("env",),
    "#!/bin/busybox sh": ("busybox", "sh"),
    "#!/usr/bin/python3 -u": ("python3", "-u"),
    "#!/usr/bin/env node": ("node",),
    "#!": (),
    "#!   ": (),
    "# !/bin/sh": (),
    " #!/bin/sh": (),
}


@pytest.mark.parametrize(("line", "expected"), SHEBANGS.items(), ids=SHEBANGS.keys())
def test_shebang_interpreter(sn: ModuleType, line: str, expected: tuple[str, ...]) -> None:
    assert sn.interpreter(line + "\nrest\n") == expected
    assert sn.interpreter(line + "\r\n") == expected
    assert sn.sniff((line + "\n").encode("utf-8")).interpreter == expected


@pytest.mark.parametrize(
    "name",
    [
        "sh",
        "bash",
        "dash",
        "ksh",
        "zsh",
        "ash",
        "mksh",
        "pdksh",
        "yash",
        "posh",
        "rbash",
        "csh",
        "tcsh",
        "fish",
        "ksh93",
        "bash5.2",
    ],
)
def test_every_shell_is_a_shell(sn: ModuleType, name: str) -> None:
    result = sn.sniff(f"#!/usr/bin/{name}\n".encode())
    assert result.kinds("high") == {"script", "shell"}
    assert result.candidates[1].signal == f"#! {name}"


@pytest.mark.parametrize(
    ("line", "kinds"),
    [
        ("#!/bin/busybox sh", {"script", "shell"}),
        ("#!/bin/toybox ash", {"script", "shell"}),
        ("#!/bin/busybox", {"script"}),
        ("#!/bin/busybox awk", {"script"}),
        ("#!/usr/bin/python3", {"script"}),
        ("#!/usr/bin/env perl -w", {"script"}),
        ("#!/usr/bin/env", {"script"}),
        ("#!/usr/bin/shellcheck", {"script"}),
        ("#!/usr/bin/ssh", {"script"}),
    ],
)
def test_what_is_and_is_not_a_shell(sn: ModuleType, line: str, kinds: set[str]) -> None:
    assert sn.sniff(f"{line}\n".encode()).kinds() == kinds
