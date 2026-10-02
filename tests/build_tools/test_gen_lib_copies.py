"""tools/gen_lib_copies.py: every lib/ copy a policy ships is generated, declared, and equal to its source."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import gen_lib_copies
import pytest
from build_tools.libcat import SHARED, make
from build_tools.libcat import copy as _copy
from build_tools.libcat import declare as _declare
from build_tools.libcat import put as _put
from trees import ROOT


@pytest.fixture
def cat(tmp_path: Path) -> Path:
    return make(tmp_path)


def test_the_real_catalog_has_no_drift() -> None:
    """The drift test: every copy under a published tree is declared and equals lib/, byte for byte."""
    assert gen_lib_copies.problems(ROOT) == []
    want, _ = gen_lib_copies.structure(ROOT)
    assert want
    assert [
        d for d, s in want.items() if hashlib.sha256(d.read_bytes()).digest() != hashlib.sha256(s.read_bytes()).digest()
    ] == []


def test_chock_shellparse_is_generated_into_every_python_command_guard() -> None:
    want, _ = gen_lib_copies.structure(ROOT)
    shipping = {d.parent.parent.parent.name for d in want if d.parent.name == "chock_shellparse"}
    on_disk = {p.parent.parent.name for p in (ROOT / "base").glob("*/implementations/chock_shellparse")}
    assert shipping == on_disk
    assert len(on_disk) >= 9


def test_write_makes_the_declared_copies_and_check_then_passes(cat: Path) -> None:
    assert gen_lib_copies.problems(cat) == [
        "base/one/implementations/pkg/__init__.py: missing (copy of lib/pkg/__init__.py)",
        "base/one/implementations/pkg/a.py: missing (copy of lib/pkg/a.py)",
        "base/one/implementations/pkg/b.py: missing (copy of lib/pkg/b.py)",
    ]
    changed, found = gen_lib_copies.write(cat)
    assert found == []
    assert changed == [f"base/one/implementations/pkg/{n}.py" for n in ("__init__", "a", "b")]
    assert sorted(p.name for p in _copy(cat).iterdir()) == ["__init__.py", "a.py", "b.py"]
    assert gen_lib_copies.problems(cat) == []
    result = gen_lib_copies.write(cat)
    assert result == ([], [])


def test_an_edited_copy_is_drift_and_write_restores_it(cat: Path) -> None:
    gen_lib_copies.write(cat)
    _put(_copy(cat) / "b.py", "x = 2  # fixed in the copy only\n")
    assert gen_lib_copies.problems(cat) == ["base/one/implementations/pkg/b.py: differs from lib/pkg/b.py"]
    result = gen_lib_copies.write(cat)
    assert result == (["base/one/implementations/pkg/b.py"], [])
    assert (_copy(cat) / "b.py").read_text(encoding="utf-8") == SHARED["b.py"]


def test_a_file_lib_does_not_have_is_drift_and_write_removes_it(cat: Path) -> None:
    gen_lib_copies.write(cat)
    _put(_copy(cat) / "c.py", "y = 2\n")
    _put(_copy(cat) / "__pycache__" / "a.cpython-311.pyc", "")
    assert gen_lib_copies.problems(cat) == [
        "base/one/implementations/pkg/c.py: not in lib/ (remove it, or add it there)"
    ]
    result = gen_lib_copies.write(cat)
    assert result == (["base/one/implementations/pkg/c.py (removed)"], [])
    assert gen_lib_copies.problems(cat) == []


def test_write_never_removes_a_folder_inside_a_copy(cat: Path) -> None:
    gen_lib_copies.write(cat)
    _put(_copy(cat) / "sub" / "x.py", "")
    changed, found = gen_lib_copies.write(cat)
    assert (changed, found) == ([], ["base/one/implementations/pkg/sub: a folder inside a lib copy; remove it by hand"])
    assert (_copy(cat) / "sub" / "x.py").is_file()


def test_write_never_replaces_a_folder_where_a_copy_goes(cat: Path) -> None:
    (_copy(cat) / "a.py").mkdir(parents=True)
    changed, found = gen_lib_copies.write(cat)
    assert found == ["base/one/implementations/pkg/a.py: a folder where a lib copy goes; remove it by hand"]
    assert changed == ["base/one/implementations/pkg/__init__.py"]


def test_a_symlinked_copy_file_is_replaced_by_a_real_file(cat: Path, tmp_path_factory) -> None:
    gen_lib_copies.write(cat)
    outside = tmp_path_factory.mktemp("outside") / "target.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    (_copy(cat) / "b.py").unlink()
    (_copy(cat) / "b.py").symlink_to(outside)
    assert gen_lib_copies.problems(cat) == ["base/one/implementations/pkg/b.py: missing (copy of lib/pkg/b.py)"]
    result = gen_lib_copies.write(cat)
    assert result == (["base/one/implementations/pkg/b.py"], [])
    assert not (_copy(cat) / "b.py").is_symlink()
    assert outside.read_text(encoding="utf-8") == "x = 1\n"


@pytest.mark.parametrize("linked", ["implementations", "implementations/pkg"])
def test_a_symlink_on_the_way_to_a_copy_is_refused_and_nothing_is_touched_through_it(
    cat: Path, tmp_path_factory, linked: str
) -> None:
    outside = tmp_path_factory.mktemp("outside")
    _put(outside / "pkg" / "precious.txt", "keep")
    _put(outside / "precious.txt", "keep")
    link = cat / "base" / "one" / linked
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)
    problem = (
        "base/one/implementations/pkg: reached through a symlink; a copy and its implementations/ are real folders"
    )
    assert problem in gen_lib_copies.problems(cat)
    result = gen_lib_copies.write(cat)
    assert result[0] == []
    assert sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")) == [
        "pkg",
        "pkg/precious.txt",
        "precious.txt",
    ]


@pytest.mark.parametrize("blocker", ["implementations", "implementations/pkg"])
def test_a_file_where_a_copy_folder_goes_is_refused(cat: Path, blocker: str) -> None:
    _put(cat / "base" / "one" / blocker, "")
    assert f"base/one/{blocker}: a file where a folder goes" in gen_lib_copies.problems(cat)
    result = gen_lib_copies.write(cat)
    assert result[0] == []


@pytest.mark.parametrize("module", ["../helper", "../../tools/x", "a/b", "a.b", "", "b "])
def test_a_module_name_that_is_not_an_identifier_is_refused_and_nothing_is_written(cat: Path, module: str) -> None:
    _put(cat / "lib" / "helper.py", "")
    _put(cat / "base" / "one" / "implementations" / "one.sh", "guard")
    _declare(cat, f"base/one:\n  pkg: [{module!r}]\n")
    assert "base/one: pkg: must list module names (plain identifiers)" in "\n".join(gen_lib_copies.problems(cat))
    result = gen_lib_copies.write(cat)
    assert result[0] == []
    assert (cat / "base" / "one" / "implementations" / "one.sh").read_text(encoding="utf-8") == "guard"


def test_lib_holds_only_packages_and_the_declarations(cat: Path) -> None:
    _put(cat / "lib" / "helper.py", "")
    assert gen_lib_copies.problems(cat) == ["lib/helper.py: lib/ holds packages and consumers.yaml only"]


def test_a_key_given_twice_is_refused(cat: Path) -> None:
    _declare(cat, "base/one:\n  pkg: [a, b]\nbase/one:\n  pkg: [b]\n")
    assert gen_lib_copies.problems(cat)[0].startswith("lib/consumers.yaml: not YAML (duplicate key base/one")
    _declare(cat, "base/one:\n  pkg: [a, b]\n  pkg: [b]\n")
    assert gen_lib_copies.problems(cat)[0].startswith("lib/consumers.yaml: not YAML (duplicate key pkg")


@pytest.mark.parametrize("where", ["implementations/vendor/pkg", "implementations/PKG", "implementations/x/Pkg"])
def test_a_copy_at_another_depth_or_case_is_refused(cat: Path, where: str) -> None:
    gen_lib_copies.write(cat)
    _put(cat / "base" / "two" / where / "__init__.py", "")
    assert gen_lib_copies.problems(cat) == [f"base/two/{where}: a lib copy no entry in lib/consumers.yaml declares"]


def test_an_undeclared_copy_is_refused(cat: Path) -> None:
    _put(_copy(cat, "two") / "__init__.py", SHARED["__init__.py"])
    assert gen_lib_copies.problems(cat) == [
        "base/two/implementations/pkg: a lib copy no entry in lib/consumers.yaml declares"
    ]


def test_a_list_missing_an_imported_module_is_refused(cat: Path) -> None:
    _declare(cat, "base/one:\n  pkg: [a]\n")
    assert gen_lib_copies.problems(cat) == [
        "lib/consumers.yaml: base/one: pkg.a imports pkg.b, which is not listed for it"
    ]


@pytest.mark.parametrize(
    ("consumers", "problem"),
    [
        ("[a, b]\n", "lib/consumers.yaml: must map policy paths to {package: [module, ...]}"),
        ("base/one: [pkg]\n", "lib/consumers.yaml: base/one: must map packages to module lists"),
        ("base/one: {}\n", "lib/consumers.yaml: base/one: must map packages to module lists"),
        ("base/one:\n  nope: [a]\n", "lib/consumers.yaml: base/one: nope: no such package under lib/"),
        ("base/one:\n  pkg: a\n", "lib/consumers.yaml: base/one: pkg: must list module names"),
        ("base/one:\n  pkg: [1]\n", "lib/consumers.yaml: base/one: pkg: must list module names"),
        ("base/one:\n  pkg: [b, b]\n", "lib/consumers.yaml: base/one: pkg: lists a module twice"),
        (
            "base/one:\n  pkg: [__init__]\n",
            "lib/consumers.yaml: base/one: pkg: no module __init__ (its __init__.py always ships)",
        ),
        ("base/one:\n  pkg: [zz]\n", "lib/consumers.yaml: base/one: pkg: no module zz (its __init__.py always ships)"),
        ("nowhere/one:\n  pkg: [b]\n", "lib/consumers.yaml: nowhere/one: not a policy folder"),
        ("base/nope:\n  pkg: [b]\n", "lib/consumers.yaml: base/nope: not a policy folder"),
        ("base:\n  pkg: [b]\n", "lib/consumers.yaml: base: not a policy folder"),
        ("base/one/x:\n  pkg: [b]\n", "lib/consumers.yaml: base/one/x: not a policy folder"),
        ("base/../base/one:\n  pkg: [b]\n", "lib/consumers.yaml: base/../base/one: not a policy folder"),
        ("base/one: [\n", "lib/consumers.yaml: not YAML"),
    ],
)
def test_a_malformed_declaration_is_refused(cat: Path, consumers: str, problem: str) -> None:
    _declare(cat, consumers)
    assert gen_lib_copies.problems(cat)[0].startswith(problem)
    result = gen_lib_copies.write(cat)
    assert result[0] == []


def test_a_symlinked_policy_folder_is_refused(cat: Path) -> None:
    (cat / "base" / "alias").symlink_to(cat / "base" / "two", target_is_directory=True)
    _declare(cat, "base/alias:\n  pkg: [b]\n")
    assert gen_lib_copies.problems(cat)[0] == "lib/consumers.yaml: base/alias: a symlink, not a policy folder"


def test_an_empty_or_missing_declaration_file(cat: Path) -> None:
    _declare(cat, "# nothing consumes lib yet\n")
    assert gen_lib_copies.problems(cat) == []
    (cat / "lib" / "consumers.yaml").unlink()
    assert gen_lib_copies.problems(cat) == ["lib/consumers.yaml: missing"]


def test_a_catalog_without_lib(tmp_path: Path) -> None:
    assert gen_lib_copies.packages(tmp_path) == {}
    assert gen_lib_copies.problems(tmp_path) == ["lib/consumers.yaml: missing"]


def test_a_package_holds_only_real_flat_python_files(cat: Path, tmp_path_factory) -> None:
    pkg = cat / "lib" / "pkg"
    _put(pkg / "data.json", "{}")
    _put(pkg / "sub" / "x.py", "")
    _put(pkg / "__pycache__" / "a.pyc", "")
    (pkg / "link.py").symlink_to(pkg / "b.py")
    _put(cat / "lib" / "orphan" / "x.py", "")
    outside = tmp_path_factory.mktemp("elsewhere")
    _put(outside / "__init__.py", "")
    (cat / "lib" / "linked").symlink_to(outside, target_is_directory=True)
    _put(cat / "lib" / "bad-name" / "__init__.py", "")
    assert gen_lib_copies.problems(cat) == [
        "lib/orphan: a folder with no __init__.py",
        "lib/bad-name: not a Python package name, or a symlink",
        "lib/linked: not a Python package name, or a symlink",
        "lib/pkg/data.json: a package holds only .py files, no symlinks or subfolders",
        "lib/pkg/link.py: a package holds only .py files, no symlinks or subfolders",
        "lib/pkg/sub: a package holds only .py files, no symlinks or subfolders",
    ]


def test_main_writes_then_checks(cat: Path, capsys) -> None:
    assert gen_lib_copies.main(["--check"], cat) == 1
    assert "3 problem(s)" in capsys.readouterr().err
    assert gen_lib_copies.main([], cat) == 0
    assert "wrote base/one/implementations/pkg/a.py" in capsys.readouterr().out
    assert gen_lib_copies.main([], cat) == 0
    assert capsys.readouterr().out == "lib copies already current\n"
    assert gen_lib_copies.main(["--check"], cat) == 0
    assert capsys.readouterr().out == "every lib copy matches its source\n"
    _declare(cat, "base/one:\n  pkg: [zz]\n")
    assert gen_lib_copies.main([], cat) == 1
    assert "no module zz" in capsys.readouterr().err


def test_the_script_runs_and_the_catalog_is_current() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "gen_lib_copies.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert (proc.returncode, proc.stdout) == (0, "every lib copy matches its source\n"), proc.stderr
