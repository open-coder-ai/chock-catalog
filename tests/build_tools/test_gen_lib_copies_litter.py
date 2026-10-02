"""tools/gen_lib_copies.py: OS litter, symlinked lib/ and implementations/, and what a refused write prints."""

from __future__ import annotations

from pathlib import Path

import gen_lib_copies
import pytest
from build_tools.libcat import copy as _copy
from build_tools.libcat import declare as _declare
from build_tools.libcat import make
from build_tools.libcat import put as _put


@pytest.fixture
def cat(tmp_path: Path) -> Path:
    return make(tmp_path)


def test_os_litter_in_lib_is_ignored_but_not_in_a_copy(cat: Path) -> None:
    _put(cat / "lib" / ".DS_Store", "")
    _put(cat / "lib" / "pkg" / ".DS_Store", "")
    (cat / "lib" / "__pycache__").mkdir()
    result = gen_lib_copies.write(cat)
    assert result[1] == []
    assert sorted(p.name for p in _copy(cat).iterdir()) == ["__init__.py", "a.py", "b.py"]
    _put(_copy(cat) / ".DS_Store", "")
    assert gen_lib_copies.problems(cat) == [
        "base/one/implementations/pkg/.DS_Store: not in lib/ (remove it, or add it there)"
    ]


def test_a_symlinked_lib_is_refused(cat: Path, tmp_path_factory) -> None:
    outside = tmp_path_factory.mktemp("elsewhere") / "lib"
    (cat / "lib").rename(outside)
    (cat / "lib").symlink_to(outside, target_is_directory=True)
    assert (
        gen_lib_copies.problems(cat)[0]
        == "lib: a symlink; lib/ is a real folder (CODEOWNERS routes review by its path)"
    )


def test_a_symlinked_implementations_folder_is_refused_and_not_walked(cat: Path, tmp_path_factory) -> None:
    outside = tmp_path_factory.mktemp("elsewhere")
    _put(outside / "pkg" / "__init__.py", "")
    (cat / "base" / "two" / "implementations").symlink_to(outside, target_is_directory=True)
    gen_lib_copies.write(cat)
    assert gen_lib_copies.problems(cat) == ["base/two/implementations: a symlink; implementations/ is a real folder"]


def test_a_refused_write_does_not_claim_the_copies_are_current(cat: Path, capsys) -> None:
    _declare(cat, "base/one:\n  pkg: [zz]\n")
    assert gen_lib_copies.main([], cat) == 1
    assert "already current" not in capsys.readouterr().out
