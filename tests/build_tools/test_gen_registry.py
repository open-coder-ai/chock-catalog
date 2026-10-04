"""tools/gen_registry.py writes the facts check_registry.py and check_readme.py verify."""

from __future__ import annotations

import re
import subprocess
import sys
from functools import partial
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


def _readme(kinds: dict[str, list[str]], evals: dict[str, tuple[int, int]], *, stale: bool) -> str:
    """A README check_readme accepts for this catalog; stale sets every count it checks to 0."""

    def n(*counted: str) -> int:
        return 0 if stale else sum(len(kinds[k]) for k in counted)

    def suite(pid: str) -> str:
        return "0/0" if stale else "{}/{}".format(*evals[pid])

    def rows(kind: str) -> str:
        return "".join(
            f"| [`{pid}`](base/{pid}) | runs `curl \\| sh` | {suite(pid)} |\n" for pid in sorted(kinds[kind])
        )

    badges = (("policies", n("gate", "guard", "text")), ("enforced", n("gate", "guard")), ("advisory", n("text")))
    return "".join(
        [
            *(f'<img alt="{v} {label}" src="https://img.shields.io/badge/{label}-{v}-blue">\n' for label, v in badges),
            f"\n| `enforced-at-commit` | the commit does not happen | {n('gate')} |\n",
            f"| `in-agent` | the tool call is refused | {n('guard')} |\n",
            f"| `advisory` | text an agent reads | {n('text')} |\n",
            f"\n**Enforced at commit**\n\n{rows('gate')}",
            f"\n**Enforced before the tool runs**\n\n{rows('guard')}",
            f"\n**Advisory**\n\n{rows('text')}",
        ]
    )


def test_the_readme_counts_it_writes_are_the_ones_check_readme_accepts(tmp_path: Path, monkeypatch) -> None:
    """Built from the catalog on disk, so it holds whether or not the committed README has caught up."""
    kinds, evals = check_readme.classify_readme()
    (tmp_path / "README.md").write_text(_readme(kinds, evals, stale=True), encoding="utf-8")
    monkeypatch.setattr(check_readme, "README", tmp_path / "README.md")
    assert check_readme.main() == 1
    assert gen_registry.update_readme(tmp_path) == "README.md counts rewritten"
    assert gen_registry.update_readme(tmp_path) == "README.md already current"
    assert check_readme.main() == 0
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == _readme(kinds, evals, stale=False)


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
    monkeypatch.setattr(gen_registry, "update_prose", lambda **_kw: "SECURITY.md counts already current")
    assert gen_registry.main([]) == 1
    assert gen_registry.main(["--check"]) == 1
    assert seen == [True, False]
    assert capsys.readouterr().out.startswith("registry.yaml done\nREADME.md is stale")


@pytest.fixture
def scoped(catalog: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """gen_registry.main pointed at the fixture catalog, with a README whose counts are stale."""
    real = (ROOT / "README.md").read_text(encoding="utf-8")
    (catalog / "README.md").write_text(re.sub(r"badge/policies-\d+-", "badge/policies-1-", real), encoding="utf-8")
    for name in ("update_registry", "update_readme"):
        monkeypatch.setattr(gen_registry, name, partial(getattr(gen_registry, name), catalog))
    monkeypatch.setattr(gen_registry, "update_prose", lambda **_kw: "SECURITY.md counts already current")
    return catalog


def test_registry_only_passes_when_just_the_readme_counts_are_stale(scoped: Path, capsys) -> None:
    assert scoped.is_dir()
    gen_registry.update_registry()
    assert gen_registry.main(["--check"]) == 1
    assert "README.md is stale" in capsys.readouterr().out
    assert gen_registry.main(["--check", "--registry-only"]) == 0
    assert capsys.readouterr().out == "registry.yaml already current\n"


def test_registry_only_fails_on_a_stale_row_and_writes_nothing_else(scoped: Path, capsys) -> None:
    readme = (scoped / "README.md").read_text(encoding="utf-8")
    assert gen_registry.main(["--check", "--registry-only"]) == 1
    assert "registry.yaml is stale" in capsys.readouterr().out
    assert gen_registry.main(["--registry-only"]) == 0
    assert gen_registry.main(["--check", "--registry-only"]) == 0
    assert (scoped / "README.md").read_text(encoding="utf-8") == readme


def test_the_committed_registry_rows_are_what_the_script_writes() -> None:
    """Run as a script, the way CI runs it. README and prose counts lag until release: the nightly checks them."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "gen_registry.py"), "--check", "--registry-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
