"""tools/gen_registry.py writes the facts check_registry.py and check_readme.py verify."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import check_readme
import check_registry
import gen_registry
import pytest
from trees import ROOT

HEAD = "catalog: test\n# a comment the generator keeps\npolicies:\n"


def _policy(root: Path, pid: str, *, version: str = "0.0.1", counts: tuple[int, int] = (2, 1), desc: str = "") -> None:
    cases, executed = counts
    folder = root / "base" / pid
    (folder / "evals").mkdir(parents=True)
    text = desc or f"The {pid} policy, described at enough length that it has to wrap across lines."
    (folder / "manifest.yaml").write_text(
        f"id: {pid}\nversion: '{version}'\nartifact: rule\nenforcement: advise\ndescription: {text}\n",
        encoding="utf-8",
    )
    rows = "".join(
        f"  - id: tc-{n}\n    prompt: p\n    expect: e\n" + ("    execute: {command: ls}\n" if n < executed else "")
        for n in range(cases)
    )
    (folder / "evals" / "suite.yaml").write_text(f"suite:\n  cases:\n{rows}", encoding="utf-8")


def _stale_row(pid: str, description: list[str]) -> str:
    return "\n".join(
        [
            f"- id: {pid}",
            f"  path: base/{pid}",
            "  version: 0.0.0",
            "  artifact: rule",
            "  enforcement: advise",
            "  mandatory: false",
            "  mechanism: rule text only",
            "  enforces: advisory",
            "  eval_cases: 9",
            *description,
        ]
    )


@pytest.fixture
def catalog(tmp_path: Path) -> Path:
    _policy(tmp_path, "kept", version="0.0.2", counts=(3, 2))
    _policy(tmp_path, "reworded", desc="Now says something else entirely.")
    _policy(tmp_path, "added")
    kept = ["  description: The kept policy, described at enough length that it", "    has to wrap across lines."]
    rows = [_stale_row("kept", kept), _stale_row("gone", []), _stale_row("reworded", ["  description: old words"])]
    (tmp_path / "registry.yaml").write_text(HEAD + "\n".join(rows) + "\nskills: []\n", encoding="utf-8")
    return tmp_path


def _rows(root: Path) -> dict[str, dict]:
    loaded = __import__("yaml").safe_load((root / "registry.yaml").read_text(encoding="utf-8"))
    return {row["id"]: row for row in loaded["policies"]}


def test_rows_are_rebuilt_from_the_policies_on_disk(catalog: Path) -> None:
    assert gen_registry.update_registry(catalog) == "registry.yaml rewritten (3 rows; removed gone)"
    rows = _rows(catalog)
    assert list(rows) == ["kept", "reworded", "added"]
    assert (rows["kept"]["version"], rows["kept"]["eval_cases"], rows["kept"]["eval_executed"]) == ("0.0.2", 3, 2)
    assert rows["added"]["eval_cases"] == 2
    assert rows["added"]["eval_executed"] == 1
    assert rows["reworded"]["description"] == "Now says something else entirely."


def test_a_description_that_still_says_the_same_keeps_its_wrapping(catalog: Path) -> None:
    gen_registry.update_registry(catalog)
    text = (catalog / "registry.yaml").read_text(encoding="utf-8")
    assert "  description: The kept policy, described at enough length that it\n    has to wrap" in text
    assert text.startswith(HEAD)
    assert text.endswith("skills: []\n")


def test_a_second_run_changes_nothing(catalog: Path) -> None:
    gen_registry.update_registry(catalog)
    assert gen_registry.update_registry(catalog) == "registry.yaml already current"


def test_a_registry_without_a_trailing_section_is_rewritten(tmp_path: Path) -> None:
    _policy(tmp_path, "only")
    (tmp_path / "registry.yaml").write_text(HEAD, encoding="utf-8")
    assert gen_registry.update_registry(tmp_path) == "registry.yaml rewritten (1 rows)"
    assert list(_rows(tmp_path)) == ["only"]


def test_the_committed_registry_is_what_the_generator_writes() -> None:
    head, rows, tail = gen_registry.split_rows((ROOT / "registry.yaml").read_text(encoding="utf-8").splitlines())
    assert head[-1] == "policies:"
    assert all(rows.values())
    for row in rows.values():
        pid = row[0].removeprefix("- id: ")
        fresh = gen_registry.render_row(gen_registry.facts(ROOT / _rows(ROOT)[pid]["path"]), row)
        assert [line for line in row if line.strip()] == fresh, pid
    assert tail == []


def test_the_readme_counts_it_writes_are_the_ones_check_readme_accepts(tmp_path: Path, monkeypatch) -> None:
    real = (ROOT / "README.md").read_text(encoding="utf-8")
    broken = re.sub(r"badge/policies-\d+-", "badge/policies-1-", real)
    broken = re.sub(r'alt="\d+ advisory"', 'alt="1 advisory"', broken)
    broken = re.sub(r"(\| `in-agent` \|[^|]*\|[ \t]*)\d+", r"\g<1>0", broken)
    broken = re.sub(r"(`pin-github-actions`\]\([^)]*\)[^\n]*\|[ \t]*)\d+/\d+", r"\g<1>1/2", broken)
    assert broken != real
    (tmp_path / "README.md").write_text(broken, encoding="utf-8")
    assert gen_registry.update_readme(tmp_path) == "README.md counts rewritten"
    assert gen_registry.update_readme(tmp_path) == "README.md already current"
    monkeypatch.setattr(check_readme, "README", tmp_path / "README.md")
    assert check_readme.main() == 0
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == real


def test_eval_counts_are_read_the_way_check_registry_reads_them() -> None:
    policy = ROOT / "base" / "pin-github-actions"
    row = gen_registry.facts(policy)
    assert (row["eval_executed"], row["eval_cases"]) == check_registry.suite_counts(policy)


def test_check_mode_writes_nothing_and_fails_on_drift(catalog: Path) -> None:
    before = (catalog / "registry.yaml").read_text(encoding="utf-8")
    assert (
        gen_registry.update_registry(catalog, write=False) == "registry.yaml is stale: run python tools/gen_registry.py"
    )
    assert (catalog / "registry.yaml").read_text(encoding="utf-8") == before


def test_main(monkeypatch, capsys) -> None:
    seen = []
    monkeypatch.setattr(gen_registry, "update_registry", lambda *, write: seen.append(write) or "registry.yaml done")
    monkeypatch.setattr(gen_registry, "update_readme", lambda **_kw: "README.md is stale: run it")
    assert gen_registry.main([]) == 1
    assert gen_registry.main(["--check"]) == 1
    assert seen == [True, False]
    assert capsys.readouterr().out.startswith("registry.yaml done\nREADME.md is stale")


def test_the_committed_files_are_what_the_generator_writes() -> None:
    """Run as a script, the way CI and regen_all.py run it."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "gen_registry.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
