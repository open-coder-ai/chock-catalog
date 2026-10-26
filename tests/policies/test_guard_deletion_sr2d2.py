"""guard-deletion: rename and copy headers are unquoted as git quotes them, so scope moves are judged on the real names."""

from __future__ import annotations

import pytest
from policies import scriptkit
from policies.guard_deletion_kit import SCOPE, hunks, scope, shipped

with shipped():
    gate = scriptkit.load("guard-deletion", "guard-deletion-gate.py")


def renamed(old: str, new: str, verb: str = "rename") -> str:
    return f"diff --git a/x b/x\nsimilarity index 100%\n{verb} from {old}\n{verb} to {new}\n"


@pytest.mark.parametrize(
    ("quoted", "plain"),
    [
        ('"tests/a\\"b.py"', 'tests/a"b.py'),
        ('"tests/a\\\\b.py"', "tests/a\\b.py"),
        ('"tests/a\\tb.py"', "tests/a\tb.py"),
        ('"tests/a\\nb.py"', "tests/a\nb.py"),
        ('"tests/a\\ab.py"', "tests/a\ab.py"),
        ('"tests/a\\bb.py"', "tests/a\bb.py"),
        ('"tests/a\\fb.py"', "tests/a\fb.py"),
        ('"tests/a\\rb.py"', "tests/a\rb.py"),
        ('"tests/a\\vb.py"', "tests/a\vb.py"),
        ('"tests/a\\001b.py"', "tests/a\x01b.py"),
        ('"tests/caf\\303\\251.py"', "tests/café.py"),
    ],
)
def test_rename_and_copy_names_are_unquoted(quoted: str, plain: str) -> None:
    for verb in ("rename", "copy"):
        (out,) = hunks.parse_patch(renamed("src/auth.py", quoted, verb))
        assert (out.old, out.path) == ("src/auth.py", plain)
        (back,) = hunks.parse_patch(renamed(quoted, "src/auth.py", verb))
        assert (back.old, back.path) == (plain, "src/auth.py")


def test_a_quoted_rename_out_of_tests_is_a_move_into_scope_and_out_again() -> None:
    (out,) = hunks.parse_patch(renamed("src/auth.py", '"tests/a\\"b.py"'))
    assert scope.in_scope(out.old, SCOPE) and not scope.in_scope(out.path, SCOPE)
    found = gate.moves([out], SCOPE)
    assert [f.family for f in found] == ["moved-out-of-scope"]
    (back,) = hunks.parse_patch(renamed('"tests/a\\"b.py"', "src/auth.py"))
    assert [f.family for f in gate.moves([back], SCOPE, inward=True)] == ["moved-into-scope"]


def test_the_plain_header_names_still_read_as_before() -> None:
    (plain,) = hunks.parse_patch(renamed("o.py", "n.py"))
    assert (plain.old, plain.path) == ("o.py", "n.py")
    (hunk,) = hunks.parse_patch('--- a/x.py\n+++ "b/y\\"z.py"\n@@ -1 +1 @@\n-a\n+b\n')
    assert (hunk.old, hunk.path) == ("x.py", 'y"z.py')
