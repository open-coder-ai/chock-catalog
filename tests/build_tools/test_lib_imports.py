"""tools/lib_imports.py: a declared module list, or a policy's own script, never imports an unlisted lib module."""

from __future__ import annotations

from pathlib import Path

import gen_lib_copies
import lib_imports
import pytest
from build_tools.libcat import declare as _declare
from build_tools.libcat import make
from build_tools.libcat import put as _put


@pytest.fixture
def cat(tmp_path: Path) -> Path:
    return make(tmp_path)


@pytest.mark.parametrize(
    ("script", "problem"),
    [
        ("from pkg import c\n", "lib/consumers.yaml: base/one: one.py imports pkg.c, which is not listed for it"),
        ("import pkg.c\n", "lib/consumers.yaml: base/one: one.py imports pkg.c, which is not listed for it"),
        ("from . import x\n", "lib/consumers.yaml: base/one: one.py: cannot be read for imports"),
    ],
)
def test_a_policy_script_importing_an_unlisted_module_is_refused(cat: Path, script: str, problem: str) -> None:
    _put(cat / "base" / "one" / "implementations" / "one.py", script)
    assert gen_lib_copies.problems(cat)[0].startswith(problem)


def test_a_policy_that_lists_nothing_but_imports_lib_is_refused(cat: Path) -> None:
    _put(cat / "base" / "two" / "implementations" / "two.py", "from pkg.b import x\n")
    assert gen_lib_copies.problems(cat) == [
        "lib/consumers.yaml: base/two: two.py imports pkg.__init__, which is not listed for it",
        "lib/consumers.yaml: base/two: two.py imports pkg.b, which is not listed for it",
    ]
    _put(cat / "base" / "two" / "implementations" / "two.py", "import os\n")
    gen_lib_copies.write(cat)
    assert gen_lib_copies.problems(cat) == []


@pytest.mark.parametrize(
    ("source", "needs"),
    [
        ("from . import b\n", {"b"}),
        ("from . import not_a_module\n", set()),
        ("from pkg import b\n", {"b"}),
        ("from pkg.b import x\n", {"b"}),
        ("import pkg.b\n", {"b"}),
        ("import pkg\n", set()),
        ("import os\nfrom os import path\n", None),
        ("def f():\n    from .b import x\n", {"b"}),
    ],
)
def test_every_import_spelling_of_a_lib_module_is_followed(cat: Path, source: str, needs: set[str] | None) -> None:
    _put(cat / "lib" / "pkg" / "c.py", source)
    found = lib_imports.imports(cat / "lib" / "pkg" / "c.py", "pkg", gen_lib_copies.packages(cat))
    assert found == (set() if needs is None else {("pkg", "__init__"), *(("pkg", n) for n in needs)})


def test_a_module_importing_another_lib_package_needs_that_package_listed(cat: Path) -> None:
    _put(cat / "lib" / "other" / "__init__.py", "")
    _put(cat / "lib" / "other" / "z.py", "")
    _put(cat / "lib" / "pkg" / "b.py", "from other.z import q\n")
    assert gen_lib_copies.problems(cat) == [
        "lib/consumers.yaml: base/one: pkg.b imports other.__init__, which is not listed for it",
        "lib/consumers.yaml: base/one: pkg.b imports other.z, which is not listed for it",
    ]
    _declare(cat, "base/one:\n  pkg: [a, b]\n  other: [z]\n")
    gen_lib_copies.write(cat)
    assert gen_lib_copies.problems(cat) == []


@pytest.mark.parametrize(
    ("source", "problem"),
    [
        ("from ..up import x\n", "lib/consumers.yaml: base/one: pkg.b: cannot be read for imports (b.py: a relative"),
        ("def (:\n", "lib/consumers.yaml: base/one: pkg.b: cannot be read for imports (invalid syntax"),
    ],
)
def test_a_module_that_cannot_be_read_for_imports_is_refused(cat: Path, source: str, problem: str) -> None:
    _put(cat / "lib" / "pkg" / "b.py", source)
    assert gen_lib_copies.problems(cat)[0].startswith(problem)


def test_a_script_in_a_subfolder_of_implementations_is_checked_too(cat: Path) -> None:
    _put(cat / "base" / "one" / "implementations" / "gate" / "rules" / "uses.py", "from pkg.c import y\n")
    assert gen_lib_copies.problems(cat) == [
        "lib/consumers.yaml: base/one: uses.py imports pkg.c, which is not listed for it"
    ]


def test_the_lib_copies_themselves_are_not_read_as_policy_scripts(cat: Path) -> None:
    gen_lib_copies.write(cat)
    _put(cat / "lib" / "pkg" / "c.py", "from pkg.b import x\n")
    _put(cat / "base" / "one" / "implementations" / "__pycache__" / "junk.py", "from pkg.c import y\n")
    assert gen_lib_copies.problems(cat) == []


def test_a_policys_own_package_may_import_its_siblings_relatively(cat: Path) -> None:
    own = cat / "base" / "one" / "implementations" / "own"
    _put(own / "__init__.py", "from .rules import R\nfrom . import more\n")
    _put(own / "rules.py", "from .more import M\n")
    _put(own / "more.py", "M = 1\n")
    gen_lib_copies.write(cat)
    assert gen_lib_copies.problems(cat) == []
    _put(own / "rules.py", "from pkg.c import y\nfrom .more import M\n")
    assert gen_lib_copies.problems(cat) == [
        "lib/consumers.yaml: base/one: rules.py imports pkg.c, which is not listed for it"
    ]
    _put(own / "rules.py", "from ..up import x\n")
    assert gen_lib_copies.problems(cat)[0].startswith(
        "lib/consumers.yaml: base/one: rules.py: cannot be read for imports"
    )
