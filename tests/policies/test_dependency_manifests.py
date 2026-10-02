"""verify-dependency-exists: the script gate that judges every written manifest and lockfile against the allowlist."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
from policies import depkit, scriptkit

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
    assert mod.load_allowlist(root) == ["requests", "Flask"]


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


def test_case_sensitive_ecosystems_compare_names_as_written() -> None:
    allowed = mod.Allowed(["github.com/BurntSushi/toml", "Org.Acme:Core", "Flask", "Newtonsoft.Json"])
    assert ("go", "github.com/BurntSushi/toml") in allowed
    assert ("go", "github.com/burntsushi/toml") not in allowed
    assert ("maven", "Org.Acme:Core") in allowed
    assert ("maven", "org.acme:core") not in allowed
    assert ("py", "flask") in allowed
    assert ("nuget", "newtonsoft.json") in allowed


def test_a_go_module_that_differs_only_in_case_is_a_new_name(tmp_path: Path) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {ALLOWLIST: "github.com/BurntSushi/toml\n"})
    ok = run(root, {"go.mod": "module m\nrequire github.com/BurntSushi/toml v1.0.0\n"})
    squat = run(root, {"go.mod": "module m\nrequire github.com/burntsushi/toml v1.0.0\n"})
    assert (ok[0], keys(ok[1])) == (0, [])
    assert (squat[0], keys(squat[1])) == (1, ["go|github.com/burntsushi/toml"])


def test_a_name_in_two_tables_of_one_file_is_one_finding(repo: Path) -> None:
    text = '[project]\ndependencies = ["evil"]\n[dependency-groups]\ndev = ["Evil"]\n'
    assert keys(run(repo, {"pyproject.toml": text})[1]) == ["py|evil"]


def test_a_lockfile_name_alone_asks(repo: Path) -> None:
    lock = '{"packages": {"": {}, "node_modules/evil-transitive": {}, "node_modules/requests": {}}}'
    code, document, err = run(repo, {"package-lock.json": lock})
    assert (code, keys(document)) == (3, ["npm|evil-transitive"])
    assert "Unlisted lockfile package" in err
    assert "pinned in the lockfile" in err


def test_a_manifest_name_beside_a_lockfile_name_blocks_and_only_the_manifest_is_judged(repo: Path) -> None:
    writes = {
        "package.json": '{"dependencies": {"evil": "1"}}',
        "package-lock.json": '{"packages": {"node_modules/evil": {}, "node_modules/its-transitive": {}}}',
    }
    code, document, err = run(repo, writes)
    assert (code, [item["path"] for item in document["findings"]]) == (1, ["package.json"])
    assert "Unlisted dependency refused" in err


def test_a_listed_manifest_addition_does_not_ask_about_its_lockfile_transitives(repo: Path) -> None:
    writes = {
        "package.json": '{"dependencies": {"requests": "2"}}',
        "package-lock.json": '{"packages": {"node_modules/requests": {}, "node_modules/its-transitive": {}}}',
    }
    assert run(repo, writes)[:2] == (0, {"findings": []})


@pytest.mark.parametrize(
    ("manifest", "lock", "asks"),
    [
        ("package.json", "package-lock.json", False),
        ("web/package.json", "package-lock.json", False),
        ("package.json", "web/package-lock.json", True),
        ("web/package.json", "api/package-lock.json", True),
        ("Cargo.toml", "package-lock.json", True),
        ("go.mod", "go.sum", False),
        ("pyproject.toml", "uv.lock", False),
    ],
)
def test_a_lockfile_is_covered_by_a_manifest_of_its_ecosystem_in_its_folder_or_below(
    repo: Path, manifest: str, lock: str, asks: bool
) -> None:
    body = {"go.sum": "example.com/new v1.0.0 h1:x=\n", "uv.lock": '[[package]]\nname = "new"\n'}
    lock_text = body.get(lock, '{"packages": {"node_modules/new": {}}}')
    manifest_text = {"package.json": "{}", "go.mod": "module m\n", "Cargo.toml": "", "pyproject.toml": ""}[
        manifest.rsplit("/", 1)[-1]
    ]
    code, document, _ = run(repo, {manifest: manifest_text, lock: lock_text})
    assert (code, [item["path"] for item in document["findings"]]) == ((3, [lock]) if asks else (0, []))


def test_a_doctype_is_a_finding_so_no_name_hides_behind_it(repo: Path) -> None:
    pom = '<!DOCTYPE project [<!ENTITY xxe "boom">]><project><dependencies><dependency><groupId>g</groupId><artifactId>&xxe;</artifactId></dependency></dependencies></project>'
    code, document, err = run(repo, {"pom.xml": pom})
    assert code == 1
    assert [k.rsplit("|", 1)[0] for k in keys(document)] == ["refused|RefusedError"]
    assert "DOCTYPE or ENTITY" in err
    assert "boom" not in err


def test_a_manifest_that_cannot_be_parsed_asks_and_is_never_a_silent_pass(repo: Path) -> None:
    code, document, err = run(repo, {"package.json": "{not json"})
    assert (code, [k.rsplit("|", 1)[0] for k in keys(document)]) == (3, ["unreadable|JSONDecodeError"])
    assert "could not be parsed (JSONDecodeError)" in err
    toml11 = '[dependencies]\nevil = {\n  version = "1",\n}\n'
    assert run(repo, {"Cargo.toml": toml11})[0] == 3
    mixed = run(repo, {"pom.xml": "<project>", "requirements.txt": "evil\n"})
    assert (mixed[0], len(mixed[1]["findings"])) == (1, 2)


def test_a_manifest_too_large_or_too_deep_to_read_is_a_finding_not_a_pass(repo: Path) -> None:
    big = "x" * (mod.MAX_CHARS + 1)
    deep = '{"x": ' + "[" * 300_000 + "]" * 300_000 + ', "dependencies": {"evil": "1"}}'
    for path, text in (("requirements.txt", big), ("package.json", deep)):
        code, document, err = run(repo, {path: text})
        assert code == 1
        assert keys(document)[0].startswith("refused|")
        assert "dependencies cannot be checked" in err


def test_an_unreadable_lockfile_asks_and_a_changed_unreadable_manifest_is_new(repo: Path) -> None:
    deep = '{"x": ' + "[" * 300_000 + "]" * 300_000 + "}"
    assert run(repo, {"package-lock.json": deep})[0] == 3
    first = keys(run(repo, {"package.json": deep})[1])
    second = keys(run(repo, {"package.json": deep + " "})[1])
    assert first != second


def test_a_pip_comment_ending_in_a_backslash_does_not_hide_the_next_requirement(repo: Path) -> None:
    code, document, _ = run(repo, {"requirements.txt": "# note \\\nevil-pkg==1.0\nrequests\n"})
    assert (code, keys(document)) == (1, ["py|evil-pkg"])


def test_node_modules_manifests_are_not_the_projects_own(repo: Path) -> None:
    writes = {
        "node_modules/dep/package.json": '{"dependencies": {"evil": "1"}}',
        "a/node_modules/x/Gemfile": "gem 'evil'",
    }
    assert run(repo, writes)[:2] == (0, {"findings": []})


def test_an_unreadable_lockfile_beside_a_manifest_is_still_refused(repo: Path) -> None:
    deep = '{"x": ' + "[" * 5000 + "]" * 5000 + "}"
    writes = {"package.json": '{"dependencies": {"requests": "1"}}', "package-lock.json": deep}
    code, document, _ = run(repo, writes)
    assert (code, [item["path"] for item in document["findings"]]) == (3, ["package-lock.json"])


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
    assert mod.line_of(["a", "foo"], "Foo") == 2
    assert mod.line_of(["a", "b"], "missing") == 1


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
