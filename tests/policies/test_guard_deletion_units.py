"""guard-deletion: hunk parsing, path scope and the shape table's validation."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from policies import scriptkit
from policies.guard_deletion_kit import IMPL, SCOPE, changes, data_table, hunks, patch, scope, shapes


def test_lines_split_on_newlines_only_and_lose_carriage_returns() -> None:
    assert hunks.lines_of("a\r\nb\u2028c\n") == ["a", "b\u2028c"]
    assert hunks.lines_of("") == []
    assert hunks.lines_of("a\nb") == ["a", "b"]


def test_from_texts_makes_one_hunk_per_changed_run() -> None:
    found = hunks.from_texts("f.py", "a\nb\nc\nd\n", "a\nB\nc\nd\ne\n")
    assert [(h.line, h.removed, h.added) for h in found] == [(2, ("b",), ("B",)), (5, (), ("e",))]


def test_a_crlf_file_compares_equal_to_its_lf_form() -> None:
    assert hunks.from_texts("f.py", "a\r\nb\r\n", "a\nb\n") == []


def test_a_huge_file_is_one_hunk_by_line_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hunks, "DIFFLIB_LINES", 2)
    found = hunks.from_texts("f.py", "a\nb\nc\n", "a\nc\nd\n")
    assert [(h.removed, h.added) for h in found] == [(("b",), ("d",))]
    assert hunks.from_texts("f.py", "a\nb\nc\n", "c\nb\na\n") == []


def test_patch_parsing_reads_paths_lines_and_crlf() -> None:
    text = patch("src/a b.py", ["if x:\r", "  y"], ["z"], start=7)
    (hunk,) = hunks.parse_patch(text)
    assert (hunk.path, hunk.line, hunk.removed, hunk.added) == ("src/a b.py", 7, ("if x:", "  y"), ("z",))


def test_content_that_looks_like_a_file_header_is_content() -> None:
    (hunk,) = hunks.parse_patch(patch("a.sql", ["-- ENABLE ROW LEVEL SECURITY"], ["++ b"]))
    assert (hunk.removed, hunk.added) == (("-- ENABLE ROW LEVEL SECURITY",), ("++ b",))


def test_a_deleted_file_is_named_by_its_old_path_and_a_pure_rename_is_a_move_note() -> None:
    gone = "diff --git a/m.js b/m.js\ndeleted file mode 100644\n--- a/m.js\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-app.use(auth)\n-x\n"
    (hunk,) = hunks.parse_patch(gone)
    assert (hunk.path, hunk.line, hunk.removed, hunk.added) == ("m.js", 1, ("app.use(auth)", "x"), ())
    rename = "diff --git a/o.py b/n.py
similarity index 100%
rename from o.py
rename to n.py
"
    assert hunks.parse_patch(rename) == [hunks.Hunk("n.py", 1, (), (), "o.py")]


def test_a_quoted_path_is_unquoted_and_the_no_newline_marker_is_skipped() -> None:
    text = 'diff --git "a/t\\"q.py" "b/t\\"q.py"\n--- "a/t\\"q.py"\n+++ "b/t\\"q.py"\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n'
    (hunk,) = hunks.parse_patch(text)
    assert (hunk.path, hunk.removed, hunk.added) == ('t"q.py', ("a",), ("b",))
    assert hunks._name('"x\\101"', "a/") == "xA"


def test_scope_skips_tests_docs_and_vendored_code() -> None:
    out = [
        "tests/a.py",
        "src/test_a.py",
        "a_test.go",
        "web/app.spec.ts",
        "docs/x.py",
        "README.md",
        "vendor/b.py",
        "a.min.js",
        "conftest.py",
    ]
    for path in out:
        assert not scope.in_scope(path, SCOPE), path
    for path in [
        "src/app.py",
        "Makefile",
        "CMakeLists.txt",
        "src/tests_helper.py",
        "lib/testing.py",
        ".github/workflows/ci.yml",
    ]:
        assert scope.in_scope(path, SCOPE), path
    assert not scope.in_scope("", SCOPE)
    assert not scope.in_scope("SRC\\Tests\\a.py", SCOPE)


def write_table(tmp_path: Path, name: str, doc: dict) -> Path:
    folder = tmp_path / "data"
    folder.mkdir(exist_ok=True)
    path = folder / name
    path.write_text(
        json.dumps({"schema": 1, "kind": "curated", "as_of": "2026-10-02", "source": "https://example.com/x", **doc})
    )
    return path


def test_the_scope_table_refuses_a_malformed_list(tmp_path: Path) -> None:
    good = {"root_dirs": ["r"], "dirs": ["t"], "names": ["n"], "suffixes": [".m"]}
    assert scope.load(write_table(tmp_path, "s.json", good))["dirs"] == ("t",)
    for bad in ({"dirs": []}, {"names": [""]}, {"suffixes": "x"}, {"dirs": [1]}):
        with pytest.raises(data_table.TableError):
            scope.load(write_table(tmp_path, "s.json", {**good, **bad}))


GUARD = {"id": "g-one", "group": "check", "label": "a check", "pattern": r"\bif\b"}
MIT = {"id": "m-one", "label": "a flag", "trigger": "removed", "removed": r"-fx", "fix": "restore it"}


def problems(tmp_path: Path, guards: object, mitigations: object) -> str:
    with pytest.raises(data_table.TableError) as err:
        shapes.load(write_table(tmp_path, "t.json", {"guards": guards, "mitigations": mitigations}))
    return str(err.value)


def test_a_valid_minimal_table_loads_with_kept_defaulting_to_removed(tmp_path: Path) -> None:
    table = shapes.load(write_table(tmp_path, "t.json", {"guards": [GUARD], "mitigations": [MIT]}))
    assert table.mitigations[0].kept is table.mitigations[0].removed


@pytest.mark.parametrize(
    ("guards", "mitigations", "text"),
    [
        ([], [MIT], "guards must be a non-empty list"),
        ([GUARD], "x", "mitigations must be a non-empty list"),
        (["x"], [MIT], "entries must be objects"),
        ([{**GUARD, "extra": 1}], [MIT], "unknown keys: extra"),
        ([{"id": "g-one"}], [MIT], "lacks keys"),
        ([{**GUARD, "id": "Bad Id"}], [MIT], "id must be kebab-case"),
        ([{**GUARD, "label": " "}], [MIT], "label must be non-empty text"),
        ([{**GUARD, "pattern": "("}], [MIT], "does not compile"),
        ([{**GUARD, "pattern": ""}], [MIT], "regex of 1.."),
        ([{**GUARD, "pattern": "x*"}], [MIT], "matches an empty line"),
        ([{**GUARD, "group": "nope"}], [MIT], "group must be one of"),
        ([GUARD], [{**MIT, "trigger": "nope"}], "trigger must be one of"),
        ([GUARD], [{**MIT, "fix": ""}], "fix must be non-empty text"),
        ([GUARD], [{**MIT, "kept": "("}], "kept does not compile"),
        ([GUARD], [{**MIT, "trigger": "removed-or-added"}], "needs a weak pattern exactly when"),
        ([GUARD], [{**MIT, "weak": "-fy"}], "needs a weak pattern exactly when"),
        ([GUARD, {**GUARD}], [MIT], "ids must be unique"),
    ],
)
def test_the_shape_table_refuses_each_malformation(
    tmp_path: Path, guards: object, mitigations: object, text: str
) -> None:
    assert text in problems(tmp_path, guards, mitigations)


def test_the_shipped_tables_are_valid_and_every_family_has_a_distinct_id() -> None:
    table = shapes.load(IMPL / "data" / "shapes.json")
    ids = [g.id for g in table.guards] + [m.id for m in table.mitigations]
    assert len(ids) == len(set(ids)) >= 20


def test_git_that_cannot_run_or_fails_is_a_change_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(changes.subprocess, "run", boom)
    with pytest.raises(changes.ChangeError, match="could not run"):
        changes.git(tmp_path, "status")
    monkeypatch.undo()
    with pytest.raises(changes.ChangeError, match="failed"):
        changes.git(tmp_path, "rev-parse", "HEAD")


def test_ci_range_prefers_the_named_base_then_the_parent_then_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {"a": "1\n"})
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    assert changes.ci_range(root) is None
    assert changes.in_range(root) == []
    scriptkit.write(root, {"a": "2\n"})
    scriptkit.git(root, "commit", "-qam", "two")
    assert changes.ci_range(root) == ["HEAD^1", "HEAD"]
    scriptkit.git(root, "update-ref", "refs/remotes/origin/main", "HEAD^1")
    monkeypatch.setenv("GITHUB_BASE_REF", " main ")
    assert changes.ci_range(root) == ["origin/main...HEAD"]
    monkeypatch.setenv("GITHUB_BASE_REF", "nope")
    with pytest.raises(changes.ChangeError, match="does not resolve"):
        changes.ci_range(root)


def test_a_baseline_that_cannot_be_read_falls_back_to_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {"a.py": "head\n"})
    scriptkit.write(root, {"a.py": "disk\n"})
    assert changes.baseline(root, "a.py", "new\n") == "disk\n"
    assert changes.baseline(root, "missing.py", "new\n") == ""

    def boom(*_a: object, **_k: object) -> str:
        raise PermissionError

    monkeypatch.setattr(Path, "read_text", boom)
    assert changes.baseline(root, "a.py", "new\n") == "head\n"


def test_a_hunk_is_judged_when_either_side_of_a_move_is_in_scope() -> None:
    move, hunk = hunks.parse_patch(
        "diff --git a/src/a.py b/vendor/a.py\nsimilarity index 90%\nrename from src/a.py\nrename to vendor/a.py\n"
        "--- a/src/a.py\n+++ b/vendor/a.py\n@@ -2 +2,0 @@\n-    if x is None: return\n"
    )
    assert (hunk.path, hunk.old, move.old) == ("vendor/a.py", "src/a.py", "src/a.py")
    assert changes.repo_path(Path("/r"), "/r/a/../b.py") == "b.py"
    for bad in ("/elsewhere/x.py", "../x.py", ".."):
        with pytest.raises(changes.ChangeError, match="outside the repository"):
            changes.repo_path(Path("/r"), bad)


def test_a_push_events_before_commit_is_the_range_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {"a": "1\n"})
    first = changes.git(root, "rev-parse", "HEAD").strip()
    scriptkit.write(root, {"a": "2\n"})
    scriptkit.git(root, "commit", "-qam", "two")
    scriptkit.write(root, {"a": "3\n"})
    scriptkit.git(root, "commit", "-qam", "three")
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    event = tmp_path / "event.json"
    for body, want in (
        ({"before": first}, [f"{first}...HEAD"]),
        ({"before": "0" * 40}, ["HEAD^1", "HEAD"]),
        ({"before": "nope"}, ["HEAD^1", "HEAD"]),
        ({"before": "a" * 40}, ["HEAD^1", "HEAD"]),
        ([], ["HEAD^1", "HEAD"]),
    ):
        event.write_text(json.dumps(body))
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
        assert changes.ci_range(root) == want
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(tmp_path / "missing.json"))
    assert changes.ci_range(root) == ["HEAD^1", "HEAD"]
