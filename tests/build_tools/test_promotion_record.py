"""`measure_false_positives.py --record`: a promotion record written from a replay, every verdict left empty."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import check_promotion as cp
import measure_false_positives as mfp
import pytest
from build_tools.selkit import GIT, git, write
from build_tools.test_measure_false_positives import CRASH_SCRIPT, GATE, commit, script
from chock.eval.suites import load_cases
from promotion_record import eval_counts, misses_listed
from trees import ROOT

STUB_EVAL = {"block": {"caught": 1, "total": 1}, "allow": {"allowed": 2, "total": 2}}
PIN = "b" * 40
DESCRIPTION = "Blocks BAD. Misses: split lines, a call (a, b), -n. Runs: commit."


def history(path: Path, files: dict[str, str]) -> Path:
    git(path, "init", "-q", "-b", "main")
    for rel, text in files.items():
        commit(path, rel, text)
    return path


@pytest.fixture
def catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A catalog with one pack `demo` and two clean commits then one BAD in a .txt; eval counts are stubbed."""
    root = tmp_path / "cat"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write(
        root, "base/demo/manifest.yaml", f'id: demo\nversion: "2.0.0"\ndescription: "{DESCRIPTION}"\nartifact: hook\n'
    )
    write(root, "base/demo/manifest.yaml", (root / "base/demo/manifest.yaml").read_text() + _gate_block())
    write(root, ".framework-ref", PIN + "\n")
    write(
        root, f"{cp.FOLDER}/record.schema.json", (ROOT / cp.FOLDER / "record.schema.json").read_text(encoding="utf-8")
    )
    commit(root, "a.txt", "fine\n")
    commit(root, "a.txt", "fine\nBAD\n")
    monkeypatch.setattr(mfp, "eval_counts", lambda *_: STUB_EVAL)
    return root


def _gate_block() -> str:
    return "applies_to:\n  paths: ['*.txt']\nhook:\n  gate:\n" + "".join(f"    {line}\n" for line in GATE.splitlines())


@pytest.fixture
def other(tmp_path: Path) -> Path:
    """A second corpus: its own history, three clean commits."""
    path = tmp_path / "other"
    path.mkdir()
    return history(path, {"x.txt": "1\n", "y.txt": "2\n", "z.txt": "3\n"})


def build(root: Path, other: Path) -> dict:
    return mfp.build_record(root, "demo", {"r/cat": root, "r/other": other}, 300, "2026-11-28")


def test_the_record_carries_each_corpus_its_fires_and_empty_verdicts(catalog: Path, other: Path) -> None:
    rec = build(catalog, other)
    head = mfp.git(catalog, "rev-parse", "HEAD").strip()
    assert (rec["policy"], rec["version"], rec["engine"], rec["catalog"], rec["date"]) == (
        "demo",
        "2.0.0",
        PIN,
        head,
        "2026-11-28",
    )
    assert rec["corpora"] == [
        {"repo": "r/cat", "commits": 2, "judged": 2, "fires": 1},
        {"repo": "r/other", "commits": 3, "judged": 3, "fires": 0},
    ]
    assert [(t["repo"], t["path"], t["verdict"], t["reason"]) for t in rec["triage"]] == [("r/cat", "a.txt", "", "")]
    assert rec["eval"] == STUB_EVAL
    assert rec["misses"] == {"read": False, "listed": 3}
    assert (rec["correct_work_rate"], rec["bar_met"]) == (None, False)


def test_a_fresh_record_validates_but_is_not_a_record_that_holds(catalog: Path, other: Path) -> None:
    schema = json.loads((catalog / cp.FOLDER / "record.schema.json").read_text(encoding="utf-8"))
    said = cp.defects(build(catalog, other), "demo", "2.0.0", schema)
    assert said == ["has 1 fire(s) without a verdict", "does not meet the bar"]


def test_main_writes_the_record_and_says_how_many_fires_to_judge(
    catalog: Path, other: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["--record", "demo", "--root", str(catalog), "--corpus", f"r/cat={catalog}", "--corpus", f"r/other={other}"]
    assert mfp.main([*argv, "--date", "2026-11-28"]) == 0
    assert capsys.readouterr().out == "wrote measurements/promotion/demo.json: 1 fire(s) to judge\n"
    saved = json.loads((catalog / cp.FOLDER / "demo.json").read_text(encoding="utf-8"))
    assert saved["date"] == "2026-11-28"
    assert [c["repo"] for c in saved["corpora"]] == ["r/cat", "r/other"]


def test_the_date_defaults_to_today(catalog: Path, other: Path) -> None:
    assert mfp.main(["--record", "demo", "--root", str(catalog), "--corpus", f"r/other={other}"]) == 0
    saved = json.loads((catalog / cp.FOLDER / "demo.json").read_text(encoding="utf-8"))
    assert len(saved["date"]) == 10


@pytest.mark.parametrize("extra", [["demo"], []])
def test_record_needs_a_corpus_and_takes_no_pack_ids(catalog: Path, extra: list[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        mfp.main(["--record", "demo", *extra, "--root", str(catalog)])
    assert stop.value.code == 2


def test_record_refuses_a_shallow_corpus_even_with_allow_shallow(
    catalog: Path, other: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    clone = tmp_path / "clone"
    subprocess.run([GIT, "clone", "-q", "--depth", "1", f"file://{other}", str(clone)], check=True, capture_output=True)
    argv = ["--record", "demo", "--root", str(catalog), "--corpus", f"r/clone={clone}", "--allow-shallow"]
    assert mfp.main(argv) == 2
    assert "shallow" in capsys.readouterr().err
    assert not (catalog / cp.FOLDER / "demo.json").exists()


def test_a_pack_that_cannot_be_replayed_is_refused_not_recorded(
    catalog: Path, other: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert mfp.main(["--record", "ghost", "--root", str(catalog), "--corpus", f"r/other={other}"]) == 2
    assert "ghost cannot be measured: no such pack" in capsys.readouterr().err


def test_a_gate_that_could_not_decide_a_commit_is_refused_not_recorded(
    catalog: Path, other: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    script(catalog, "boom", CRASH_SCRIPT)
    write(catalog, "base/boom/manifest.yaml", (catalog / "base/boom/manifest.yaml").read_text() + 'version: "1"\n')
    assert mfp.main(["--record", "boom", "--root", str(catalog), "--corpus", f"r/other={other}"]) == 2
    assert "could not decide 3 commit(s) in r/other" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("text", "count"),
    [
        ("Blocks x. Misses: split lines, -n. Runs: commit.", 2),
        ("Misses: a call (a, b), a member chain, an .env file", 3),
        ("Misses: aliases", 1),
        ("Misses: .  Runs on", 0),
        ("Blocks x. Runs: commit.", 0),
        ("", 0),
    ],
)
def test_misses_listed_counts_the_items_of_the_misses_sentence(text: str, count: int) -> None:
    assert misses_listed(text) == count


def test_the_description_folded_over_lines_is_read_as_one_sentence() -> None:
    assert misses_listed("Blocks x. Misses: split\n  lines, scripts,\n  aliases. Runs: commit.") == 3


def test_the_real_policys_executable_cases_are_replayed_and_prose_cases_are_not_counted() -> None:
    folder = ROOT / "base" / "scan-secrets"
    counts = eval_counts(ROOT, folder)
    assert counts["block"]["total"] > 0
    assert counts["allow"]["total"] > 0
    assert counts["block"]["caught"] == counts["block"]["total"]
    assert counts["allow"]["allowed"] == counts["allow"]["total"]


def test_a_prose_case_with_no_executable_form_is_not_counted() -> None:
    folder = ROOT / "base" / "limit-diff-size"
    counts = eval_counts(ROOT, folder)
    executable = [c for c in load_cases(folder, folder.name) if c.execute]
    assert len(executable) < len(load_cases(folder, folder.name))
    assert counts["block"]["total"] + counts["allow"]["total"] == len(executable)
