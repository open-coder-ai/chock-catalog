"""tools/measure_false_positives.py: replay a pack's gate over history, count the commits it fires on."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path

import measure_false_positives as mfp
import pytest
from build_tools.selkit import GIT, git, write

GATE = """kind: content_regex
"on": [commit]
action: warn
params: {content_pattern: BAD, scan: added_lines}
"""

SCRIPT_GATE = 'kind: script\n"on": [commit]\naction: warn\nparams: {script: gate.py}\n'

FINDING = '{"findings": [{"key": "k", "path": "a.txt", "line": 2, "rule": "r1", "message": "bad line"}]}'
FIND_SCRIPT = f"import json, sys\nw = json.load(sys.stdin)['writes']\nif any('BAD' in t for t in w.values()):\n    print('{FINDING}')\n    sys.exit(4)\n"
REFUSE_SCRIPT = "import sys\nprint('not allowed here', file=sys.stderr)\nsys.exit(1)\n"
CRASH_SCRIPT = "import sys\nprint('Traceback (most recent call last)', file=sys.stderr)\nsys.exit(1)\n"


def pack(root: Path, pid: str, gate: str | None, scope: str = '["*.txt"]', folder: str = "base") -> None:
    """A pack with a `hook.gate` made of the given indented YAML, bounded to `scope`."""
    body = f"id: {pid}\nartifact: hook\napplies_to:\n  paths: {scope}\n"
    if gate is not None:
        body += "hook:\n  gate:\n" + "".join(f"    {line}\n" for line in gate.splitlines())
    write(root, f"{folder}/{pid}/manifest.yaml", body)


def script(root: Path, pid: str, text: str, gate: str = SCRIPT_GATE) -> None:
    pack(root, pid, gate)
    write(root, f"base/{pid}/implementations/gate.py", text)


def commit(root: Path, rel: str, text: str) -> None:
    write(root, rel, text)
    git(root, "add", ".")
    git(root, "-c", "user.email=t@chock.invalid", "-c", "user.name=t", "commit", "-qm", f"add {rel}")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Three commits: ok.txt is clean, then a BAD line in a .txt (the gate's scope), then BAD in a .md (out of it)."""
    git(tmp_path, "init", "-q", "-b", "main")
    pack(tmp_path, "demo", GATE)
    commit(tmp_path, "a.txt", "fine\n")
    commit(tmp_path, "a.txt", "fine\nBAD\n")
    commit(tmp_path, "notes.md", "BAD\n")
    return tmp_path


def row(report: dict, pid: str) -> dict:
    return next(r for r in report["packs"] if r["pack"] == pid)


def test_a_gate_firing_on_one_of_two_judged_commits_is_fifty_percent(repo: Path) -> None:
    report = mfp.measure(repo, ["demo"], 300)
    demo = row(report, "demo")
    assert (demo["replayed"], demo["judged"], demo["fires"], demo["rate"]) == (3, 2, 1, 50.0)
    assert demo["details"][0]["subject"] == "add a.txt"
    assert demo["details"][0]["items"] == [{"path": "a.txt", "line": 0, "rule": "", "message": "content pattern"}]


def test_a_commit_outside_the_gates_scope_is_not_judged(repo: Path) -> None:
    pack(repo, "md-only", GATE, scope='["*.md"]')
    git(repo, "add", ".")
    git(repo, "-c", "user.email=t@chock.invalid", "-c", "user.name=t", "commit", "-qm", "pack")
    assert row(mfp.measure(repo, ["md-only"], 300), "md-only")["judged"] == 1


def test_a_pack_nothing_in_history_touches_has_no_rate(repo: Path) -> None:
    pack(repo, "never", GATE, scope='["*.nothing"]')
    demo = row(mfp.measure(repo, ["never"], 300), "never")
    assert (demo["judged"], demo["rate"]) == (0, None)
    assert "n/a" in mfp.render(mfp.measure(repo, ["never"], 300))


def test_limit_bounds_the_replay_and_the_root_commit_is_judged(repo: Path) -> None:
    assert row(mfp.measure(repo, ["demo"], 1), "demo")["replayed"] == 1
    root = row(mfp.measure(repo, ["demo"], 300), "demo")
    assert root["replayed"] == 3


def test_the_tool_writes_nothing_to_the_repo(repo: Path) -> None:
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts}
    mfp.measure(repo, ["demo"], 300)
    after = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts}
    assert before == after
    status = subprocess.run([GIT, "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True)
    assert status.stdout == ""


@pytest.mark.parametrize(
    ("gate", "reason"),
    [
        (None, "declares no hook gate"),
        ('kind: content_regex\n"on": [push]\naction: warn\n', "not judged at commit"),
        ('kind: session_state\n"on": [commit]\naction: warn\n', "cannot be replayed"),
    ],
)
def test_a_pack_that_cannot_be_replayed_is_unmeasurable(repo: Path, gate: str | None, reason: str) -> None:
    pack(repo, "odd", gate)
    odd = row(mfp.measure(repo, ["odd"], 300), "odd")
    assert odd["status"] == "unmeasurable"
    assert reason in odd["reason"]
    assert "unmeasurable" in mfp.render(mfp.measure(repo, ["odd"], 300))


def test_a_pack_that_imports_the_network_is_unmeasurable(repo: Path) -> None:
    script(repo, "net", "import socket\n")
    assert "imports socket" in row(mfp.measure(repo, ["net"], 300), "net")["reason"]


def test_an_unknown_pack_is_unmeasurable(repo: Path) -> None:
    assert row(mfp.measure(repo, ["ghost"], 300), "ghost")["reason"] == "no such pack"


def test_a_script_gate_reports_its_findings_with_rule_and_line(repo: Path) -> None:
    script(repo, "scr", FIND_SCRIPT)
    scr = row(mfp.measure(repo, ["scr"], 300), "scr")
    assert (scr["judged"], scr["fires"], scr["errors"]) == (2, 1, 0)
    assert scr["details"][0]["items"] == [{"path": "a.txt", "line": 2, "rule": "r1", "message": "bad line"}]
    assert "a.txt:2 [r1] bad line" in mfp.render(mfp.measure(repo, ["scr"], 300))


def test_a_script_that_refuses_in_words_is_a_fire_and_a_crash_is_an_error(repo: Path) -> None:
    script(repo, "words", REFUSE_SCRIPT)
    script(repo, "boom", CRASH_SCRIPT)
    report = mfp.measure(repo, ["words", "boom"], 300)
    words, boom = row(report, "words"), row(report, "boom")
    assert (words["fires"], words["errors"]) == (2, 0)
    assert words["details"][0]["items"] == [{"path": "", "line": 0, "rule": "", "message": "not allowed here"}]
    assert (boom["fires"], boom["errors"]) == (2, 2)


def test_observe_packs_are_the_ones_whose_gate_warns(repo: Path) -> None:
    pack(repo, "strict", GATE.replace("warn", "block"))
    pack(repo, "plain", None)
    write(repo, "base/empty/manifest.yaml", "")
    assert mfp.observe_packs(repo) == ["demo"]


def test_a_pack_found_under_any_top_level_folder_is_measured(repo: Path) -> None:
    pack(repo, "elsewhere", GATE, folder="agentic-security")
    assert mfp.pack_dir(repo, "elsewhere") == repo / "agentic-security" / "elsewhere"


def test_two_runs_over_the_same_range_print_the_same_json(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    runs = []
    for _ in range(2):
        assert mfp.main(["demo", "--json", "--root", str(repo)]) == 0
        runs.append(capsys.readouterr().out)
    assert runs[0] == runs[1]
    assert json.loads(runs[0])["packs"][0]["fires"] == 1


def test_the_text_report_lists_each_fire_and_the_wall_time_goes_to_stderr(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert mfp.main(["--root", str(repo)]) == 0
    seen = capsys.readouterr()
    assert "demo" in seen.out
    assert "50.0%" in seen.out
    assert "demo warn at" in seen.out
    assert seen.err.startswith("wall time ")


def test_running_the_file_as_a_script_exits_zero(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["measure_false_positives.py", "demo", "--root", str(repo)])
    with pytest.raises(SystemExit) as stop:
        runpy.run_path(mfp.__file__, run_name="__main__")
    assert stop.value.code == 0


@pytest.fixture
def shallow(repo: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A depth-2 clone of the fixture: two commits, the older one cut off from its parent."""
    dest = tmp_path_factory.mktemp("shallow") / "clone"
    subprocess.run([GIT, "clone", "-q", "--depth", "2", f"file://{repo}", str(dest)], check=True, capture_output=True)
    return dest


def test_a_shallow_boundary_commit_is_skipped_but_a_true_root_is_kept(repo: Path, shallow: Path) -> None:
    assert [subject for _, _, subject in mfp.commits(shallow, 300)] == ["add notes.md"]
    assert mfp.commits(shallow, 300)[0][1] != mfp.EMPTY_TREE
    assert mfp.commits(repo, 300)[-1][1] == mfp.EMPTY_TREE


def test_a_shallow_clone_is_refused_unless_allowed(shallow: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert mfp.main(["demo", "--root", str(shallow)]) == 2
    seen = capsys.readouterr()
    assert "shallow" in seen.err
    assert seen.out == ""
    assert mfp.main(["demo", "--allow-shallow", "--root", str(shallow)]) == 0
    assert "1 first-parent commits replayed" in capsys.readouterr().out
