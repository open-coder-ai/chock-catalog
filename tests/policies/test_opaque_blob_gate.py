"""opaque-blob-guard: the gate as a process, the data tables, the manifest scope, and the engine's verdicts."""

from __future__ import annotations

import fnmatch
import io
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from policies import blobkit, gatekit, scriptkit
from trees import ROOT

gate, ns = blobkit.load()
POLICY = blobkit.POLICY
DATA = ROOT / "base" / POLICY / "implementations" / "data"
RULE = {"id": "x", "why": "y", "anchor": "x", "window": 5, "after": "x"}
XZ = b"\xfd7zXZ\x00" + b"\0" * 24


def run(repo: Path, payload: object, name: str = blobkit.NAME) -> tuple[int, str, str]:
    proc = scriptkit.run_script_full(POLICY, name, repo, payload if isinstance(payload, str) else json.dumps(payload))
    return proc.returncode, proc.stdout, proc.stderr


def test_a_finding_exits_ask_with_a_document_and_the_way_out(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {"testdata/a.txt": XZ})
    code, out, err = run(repo, {"event": "commit", "repo_root": str(repo), "writes": {"testdata/a.txt": ""}})
    assert code == 3
    (row,) = json.loads(out)["findings"]
    assert (row["path"], row["rule"], row["line"]) == ("testdata/a.txt", "opaque-magic", 1)
    assert "xz stream" in err
    assert "blob-allowlist.txt" in err


def test_a_clean_change_exits_zero(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {"tests/a.txt": "ok\n"})
    code, out, _ = run(repo, {"event": "commit", "repo_root": str(repo), "writes": {"tests/a.txt": "ok\n"}})
    assert (code, json.loads(out)) == (0, {"findings": []})


def test_the_baseline_run_reports_nothing_so_every_finding_is_new(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {"testdata/a.txt": XZ})
    payload = {"event": "commit", "repo_root": str(repo), "writes": {"testdata/a.txt": ""}, "baseline": True}
    assert run(repo, payload)[:2] == (0, '{"findings": []}\n')


@pytest.mark.parametrize("payload", ["{}", "[]", '{"writes": []}', '{"writes": {"a": 1, "tests/b": null}}'])
def test_odd_payloads_judge_nothing(tmp_path: Path, payload: str) -> None:
    repo = blobkit.make_repo(tmp_path, {})
    assert run(repo, payload)[:2] == (0, '{"findings": []}\n')


def test_stdin_that_is_not_json_is_a_refusal_not_a_pass(tmp_path: Path) -> None:
    assert run(blobkit.make_repo(tmp_path, {}), "not json")[0] == 2


def corrupt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, **change: object) -> None:
    copy = tmp_path / "data"
    shutil.copytree(DATA, copy)
    doc = json.loads((copy / name).read_text(encoding="utf-8"))
    doc.update(change)
    (copy / name).write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setattr(ns.tables, "DATA", copy)
    ns.tables.load.cache_clear()


def test_a_broken_table_means_nothing_was_judged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    corrupt(tmp_path, monkeypatch, "scope.json", dirs=[])
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"writes": {}}'))
    try:
        assert gate.main() == 2
    finally:
        ns.tables.load.cache_clear()
    assert "nothing was judged" in capsys.readouterr().err


def test_the_manifest_globs_reach_every_scoped_path_and_only_those() -> None:
    table = json.loads((DATA / "scope.json").read_text(encoding="utf-8"))
    globs = scriptkit.manifest(POLICY)["applies_to"]["paths"]

    def reached(path: str) -> bool:
        return any(fnmatch.fnmatchcase(path, g) for g in globs)

    wrapper = table["gradle_wrapper"]
    paths = [f"{d}/a" for d in table["dirs"]] + [f"x/y/{d}/z/a" for d in table["dirs"]]
    paths += [f"{wrapper}/a", f"app/{wrapper}/a", table["allowlist"]]
    paths += [n for n in table["text_names"]] + [f"sub/{n}" for n in table["text_names"]]
    paths += [f"a{s}" for s in table["text_suffixes"]] + [f"deep/er/a{s}" for s in table["text_suffixes"]]
    assert [p for p in paths if not reached(p)] == []
    assert not any(reached(p) for p in ["src/a.xz", "docs/a.md", "README.md", "gradle/a"])


@pytest.mark.parametrize(
    ("name", "change"),
    [
        pytest.param("scope.json", {"dirs": []}, id="no-dirs"),
        pytest.param("scope.json", {"text_names": [""]}, id="empty-name"),
        pytest.param("scope.json", {"gradle_wrapper": 3}, id="wrapper-not-a-string"),
        pytest.param("magic.json", {"magic": []}, id="no-signatures"),
        pytest.param("magic.json", {"media": [{"name": "x", "at": [[-1, "00"]]}]}, id="negative-offset"),
        pytest.param("magic.json", {"magic": [{"name": "x", "at": [[0, ""]]}]}, id="empty-signature"),
        pytest.param("magic.json", {"magic": [{"name": "x", "at": [[0, "zz"]]}]}, id="not-hex"),
        pytest.param("magic.json", {"entropy": {"min_size": 1}}, id="entropy-keys"),
        pytest.param(
            "magic.json",
            {"entropy": {"min_size": 0, "window": 1, "min_tail": 1, "bits_per_byte": 7}},
            id="entropy-size",
        ),
        pytest.param(
            "magic.json",
            {"entropy": {"min_size": 1, "window": 1, "min_tail": 1, "bits_per_byte": 9}},
            id="entropy-bits",
        ),
        pytest.param("textrules.json", {"patterns": []}, id="no-patterns"),
        pytest.param("textrules.json", {"patterns": [{**RULE, "anchor": "("}]}, id="bad-regex"),
        pytest.param("textrules.json", {"patterns": [{**RULE, "id": 1}]}, id="bad-id"),
        pytest.param("textrules.json", {"patterns": [{**RULE, "before": "x"}]}, id="both-windows"),
        pytest.param("textrules.json", {"patterns": [{**RULE, "window": 0}]}, id="no-window"),
        pytest.param("gradle.json", {"known_wrapper_sha256": ["ABC"]}, id="bad-sha"),
    ],
)
def test_a_bad_table_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, change: dict) -> None:
    corrupt(tmp_path, monkeypatch, name, **change)
    try:
        with pytest.raises(ns.tables.data_table.TableError):
            ns.tables.load()
    finally:
        ns.tables.load.cache_clear()


def test_the_shipped_tables_load_and_the_known_hash_list_is_documented_empty() -> None:
    table = ns.tables.load()
    assert table.known_wrappers == frozenset()
    assert {"tests", "m4", "vendor"} <= table.dirs


@pytest.mark.parametrize(
    ("files", "verdict"),
    [
        ({"testdata/a.txt": b"PK\x03\x04" + b"\0" * 20}, "warn"),
        ({"testdata/a.txt": b"hello\n"}, "allow"),
    ],
)
def test_the_engine_warns_while_observed(tmp_path: Path, files: dict, verdict: str) -> None:
    repo = blobkit.make_repo(tmp_path, files)
    code, stderr = gatekit.judge(POLICY, repo, gatekit.COMMIT)
    assert code == 0  # a warning never stops a commit
    assert ("reviewer cannot read" in stderr) == (verdict == "warn")


def test_the_engine_judges_an_agent_write_at_tool_use(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {})
    code, stderr = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {"fixtures/a.dat": "PK\x03\x04abc"})
    assert code == 4
    assert "zip or jar archive" in stderr


def test_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {"README.md": "x\n"})
    (repo / "tests").mkdir()
    os.mkfifo(repo / "tests/pipe")
    found = blobkit.run(gate, repo, ["tests/pipe"])
    assert blobkit.rules(found) == [("tests/pipe", "unreadable")]
    assert "not a regular file" in found[0]["message"]


def test_a_folder_that_is_a_file_is_unreadable(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {"tests": "i am a file\n"})
    assert blobkit.rules(blobkit.run(gate, repo, ["tests/a/b"], event="tool_use", writes={"tests/a/b": "x"})) == [
        ("tests/a/b", "unreadable")
    ]
