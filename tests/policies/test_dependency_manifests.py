"""verify-dependency-exists: the script gate that judges every written manifest and lockfile against the allowlist."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from policies import depkit, gatekit, scriptkit

POLICY = "verify-dependency-exists"
NAME = "dependency-manifests.py"
mod, _ = depkit.load()
ALLOWLIST = ".chock/dependency-allowlist.txt"


def payload(repo: Path, writes: dict[str, str], event: str = "commit", **extra: object) -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes, **extra}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {ALLOWLIST: "requests\nacme-lib\n"})


def run(repo: Path, writes: dict[str, str], **extra: object) -> tuple[int, dict, str]:
    proc = scriptkit.run_script_full(POLICY, NAME, repo, json.dumps(payload(repo, writes, **extra)))
    return proc.returncode, json.loads(proc.stdout) if proc.stdout else {}, proc.stderr


def keys(document: dict) -> list[str]:
    return [item["key"] for item in document["findings"]]


def test_the_manifest_declares_the_script_gate() -> None:
    gate = scriptkit.manifest(POLICY)["hook"]["gate"]
    assert (gate["kind"], gate["on"], gate["action"], gate["params"]) == (
        "script",
        ["commit", "tool_use"],
        "block",
        {"script": NAME},
    )
    assert scriptkit.script_path(POLICY, "depnames/families.py").is_file()


def test_an_unlisted_name_is_a_finding_and_the_run_exits_1(repo: Path) -> None:
    code, document, err = run(repo, {"requirements.txt": "requests\nreqeusts\n"})
    assert (code, keys(document)) == (1, ["py|reqeusts"])
    assert document["findings"][0]["path"] == "requirements.txt"
    assert document["findings"][0]["line"] == 2
    assert "Ask a person to add the name" in err
    assert "no registry lookup" in err


def test_listed_and_normalised_equivalent_names_are_silent(repo: Path) -> None:
    (repo / ALLOWLIST).write_text("requests\nFoo-Bar\nserde-json\n", encoding="utf-8")
    writes = {
        "requirements.txt": "Requests==2\nfoo_bar>=1\nFOO.BAR\n",
        "Cargo.toml": '[dependencies]\nserde_json = "1"\n',
    }
    assert run(repo, writes) == (0, {"findings": []}, "")


def test_a_missing_allowlist_lists_nothing(tmp_path: Path) -> None:
    bare = scriptkit.init_repo(tmp_path / "bare", {"README.md": "x\n"})
    code, document, _ = run(bare, {"requirements.txt": "requests\n"})
    assert (code, keys(document)) == (1, ["py|requests"])


def test_allowlist_lines_tolerate_comments_blanks_bom_and_crlf(tmp_path: Path) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {})
    (root / ".chock").mkdir()
    (root / ALLOWLIST).write_bytes(b"\xef\xbb\xbf# approved\r\nrequests  # http client\r\n\r\n  Flask \r\n")
    assert mod.load_allowlist(root) == ["requests", "flask"]


def test_an_allowlist_that_is_not_utf8_lists_nothing(tmp_path: Path) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {})
    (root / ".chock").mkdir()
    (root / ALLOWLIST).write_bytes(b"\xff\xfe")
    assert mod.load_allowlist(root) == []


def test_each_ecosystem_normalises_the_allowlist_its_own_way() -> None:
    allowed = mod.Allowed(["foo_bar", "serde_json", "@scope/pkg"])
    assert ("py", "foo-bar") in allowed
    assert ("cargo", "serde-json") in allowed
    assert ("npm", "foo-bar") not in allowed
    assert ("npm", "@scope/pkg") in allowed
    assert ("py", "scope-pkg") not in allowed


def test_a_name_in_two_tables_of_one_file_is_one_finding(repo: Path) -> None:
    text = '[project]\ndependencies = ["evil"]\n[dependency-groups]\ndev = ["Evil"]\n'
    assert keys(run(repo, {"pyproject.toml": text})[1]) == ["py|evil"]


def test_a_lockfile_name_alone_asks(repo: Path) -> None:
    lock = '{"packages": {"": {}, "node_modules/evil-transitive": {}, "node_modules/requests": {}}}'
    code, document, err = run(repo, {"package-lock.json": lock})
    assert (code, keys(document)) == (3, ["npm|evil-transitive"])
    assert "Unlisted package in a lockfile" in err
    assert "pinned in the lockfile" in err


def test_a_manifest_name_beside_a_lockfile_name_blocks(repo: Path) -> None:
    writes = {
        "package.json": '{"dependencies": {"evil": "1"}}',
        "package-lock.json": '{"packages": {"node_modules/evil": {}}}',
    }
    code, document, err = run(repo, writes)
    assert code == 1
    assert sorted(item["path"] for item in document["findings"]) == ["package-lock.json", "package.json"]
    assert "Unlisted dependency refused" in err
    assert "package-lock.json" not in err


def test_a_doctype_is_a_finding_so_no_name_hides_behind_it(repo: Path) -> None:
    pom = '<!DOCTYPE project [<!ENTITY xxe "boom">]><project><dependencies><dependency><groupId>g</groupId><artifactId>&xxe;</artifactId></dependency></dependencies></project>'
    code, document, err = run(repo, {"pom.xml": pom})
    assert (code, keys(document)) == (1, ["refused|doctype"])
    assert "DOCTYPE or ENTITY" in err
    assert "boom" not in err


def test_an_unreadable_manifest_adds_no_names_and_prints_a_note(repo: Path) -> None:
    code, document, err = run(repo, {"package.json": "{not json", "pom.xml": "<project>", "requirements.txt": "evil\n"})
    assert (code, keys(document)) == (1, ["py|evil"])
    assert "package.json: could not be read as package.json (JSONDecodeError)" in err
    assert "pom.xml: could not be read as pom.xml (ParseError)" in err
    only_notes = run(repo, {"package.json": "{not json"})
    assert only_notes[:2] == (0, {"findings": []})
    assert "its dependencies were not checked" in only_notes[2]


def test_the_baseline_run_prints_findings_but_no_notes(repo: Path) -> None:
    code, document, err = run(repo, {"package.json": "{not json", "requirements.txt": "evil\n"}, baseline=True)
    assert (code, keys(document)) == (1, ["py|evil"])
    assert "could not be read" not in err


def test_a_manifest_over_the_size_limit_is_not_read(repo: Path) -> None:
    big = "x" * (mod.MAX_CHARS + 1)
    code, document, err = run(repo, {"requirements.txt": big})
    assert (code, document) == (0, {"findings": []})
    assert "requirements.txt: could not be read as requirements (ValueError)" in err


def test_files_that_are_not_manifests_are_ignored(repo: Path) -> None:
    assert run(repo, {"README.md": "requests evil", "src/app.py": "import evil\n"})[:2] == (0, {"findings": []})
    assert run(repo, {})[:2] == (0, {"findings": []})


def test_an_include_is_judged_when_the_change_holds_it_and_never_outside_the_repo(repo: Path) -> None:
    writes = {
        "requirements.txt": "requests\n-r deps/base.in\n-c ../../outside.txt\n-r /etc/passwd\n-r ../up.txt\n-r requirements.txt\n-r missing.txt\n",
        "deps/base.in": "evil-base\n-r ../deps/more.cfg\n",
        "deps/more.cfg": "evil-more\n",
        "deps/unreferenced.in": "evil-unreferenced\n",
        "up.txt": "evil-up\n",
    }
    document = run(repo, writes)[1]
    assert sorted((item["path"], item["key"]) for item in document["findings"]) == [
        ("deps/base.in", "py|evil-base"),
        ("deps/more.cfg", "py|evil-more"),
    ]


def test_an_include_outside_the_repo_is_not_read_even_when_it_exists(tmp_path: Path) -> None:
    root = scriptkit.init_repo(tmp_path / "work" / "repo", {ALLOWLIST: "requests\n"})
    (tmp_path / "outside.txt").write_text("evil-outside\n", encoding="utf-8")
    code, document, _ = run(root, {"requirements.txt": "requests\n-r ../../outside.txt\n"})
    assert (code, document) == (0, {"findings": []})


def test_windows_separators_are_normalised_in_paths(repo: Path) -> None:
    document = run(repo, {"deps\\requirements.txt": "evil\n-r base.in\n", "deps\\base.in": "evil2\n"})[1]
    assert sorted(item["path"] for item in document["findings"]) == ["deps/base.in", "deps/requirements.txt"]


def test_line_of_falls_back_to_the_first_line() -> None:
    assert mod.line_of("a\nFoo\n", "foo") == 2
    assert mod.line_of("a\nb\n", "missing") == 1


def test_malformed_input_is_a_fault_not_a_verdict(repo: Path) -> None:
    proc = scriptkit.run_script_full(POLICY, NAME, repo, "not json")
    assert proc.returncode == 2
    assert "internal error" in proc.stderr
    assert proc.stdout == ""


def test_main_reads_stdin_in_process(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", [NAME])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload(repo, {"Gemfile": "gem 'evil'\n"}))))
    assert mod.main() == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["key"] == "gem|evil"


def test_seed_prints_the_tracked_manifests_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = scriptkit.init_repo(
        tmp_path / "seed",
        {
            "requirements.txt": "Requests==2\nFoo_Bar\n",
            "sub/package.json": '{"dependencies": {"left-pad": "1"}}',
            "package-lock.json": '{"packages": {"node_modules/transitive": {}}}',
            "broken/Cargo.toml": "[dependencies",
            "README.md": "# not a manifest\n",
            "bin.txt": b"\xff\xfe",
            "requirements/bad.txt": b"\xff\xfe",
        },
    )
    monkeypatch.chdir(root)
    monkeypatch.setattr(sys, "argv", [NAME, "--seed"])
    assert mod.main() == 0
    out, err = capsys.readouterr()
    assert out.splitlines() == [
        "# Seeded from the tracked manifests; review before committing.",
        "foo-bar",
        "left-pad",
        "requests",
    ]
    assert "broken/Cargo.toml skipped (TOMLDecodeError)" in err
    assert "requirements/bad.txt skipped (UnreadableError)" in err


def test_the_seed_command_runs_as_a_process_and_its_output_is_a_working_allowlist(tmp_path: Path) -> None:
    root = scriptkit.init_repo(
        tmp_path / "seed", {"requirements.txt": "requests\nflask\n", "go.mod": "require example.com/x v1\n"}
    )
    proc = scriptkit.run_script_full(POLICY, NAME, root, "")
    assert proc.returncode == 2  # no payload on stdin
    seeded = subprocess.run(
        [sys.executable, str(scriptkit.script_path(POLICY, NAME)), "--seed"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    (root / ".chock").mkdir()
    (root / ALLOWLIST).write_text(seeded.stdout, encoding="utf-8")
    assert run(root, {"requirements.txt": "requests\nflask\n", "go.mod": "require example.com/x v1\n"})[:2] == (
        0,
        {"findings": []},
    )
    assert run(root, {"requirements.txt": "requests\nfresh\n"})[0] == 1


# Through chock's own runner: the baseline run, the three events and the verdict word.
def engine(repo: Path, event: str, writes: dict[str, str]) -> tuple[int, str]:
    return gatekit.judge(POLICY, repo, event, writes)


@pytest.fixture
def engine_repo(tmp_path: Path) -> Path:
    files = {
        ALLOWLIST: "requests\n",
        "requirements.txt": "requests\nlegacy-unlisted\n",
        "package-lock.json": '{"packages": {"node_modules/requests": {}}}',
    }
    return scriptkit.init_repo(tmp_path / "engine", files)


def test_the_engine_keeps_only_what_the_change_adds(engine_repo: Path) -> None:
    same = engine(engine_repo, gatekit.PRE_TOOL_USE, {"requirements.txt": "legacy-unlisted\nrequests\n# note\n"})
    assert same == (0, "")
    added = engine(engine_repo, gatekit.PRE_TOOL_USE, {"requirements.txt": "requests\nlegacy-unlisted\nreqeusts\n"})
    assert added[0] == 1
    assert "reqeusts" in added[1]
    assert "legacy-unlisted" not in added[1]


def test_the_engine_turns_a_lockfile_only_addition_into_an_ask(engine_repo: Path) -> None:
    lock = '{"packages": {"node_modules/requests": {}, "node_modules/evil-transitive": {}}}'
    code, err = engine(engine_repo, gatekit.PRE_TOOL_USE, {"package-lock.json": lock})
    assert code != 0
    assert "evil-transitive" in err
    both = engine(
        engine_repo,
        gatekit.PRE_TOOL_USE,
        {"package-lock.json": lock, "requirements.txt": "requests\nlegacy-unlisted\nnew-one\n"},
    )
    assert both[0] == 1
    assert "new-one" in both[1]
