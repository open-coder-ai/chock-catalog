"""verify-dependency-exists: how the allowlist file is read -- absent, empty, unreadable, normalised per ecosystem."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import depkit, scriptkit

POLICY = "verify-dependency-exists"
NAME = "dependency-manifests.py"
mod, _ = depkit.load()
ALLOWLIST = ".chock/dependency-allowlist.txt"


def run(repo: Path, writes: dict[str, str]) -> tuple[int, dict, str]:
    payload = {"event": "commit", "repo_root": str(repo), "writes": writes}
    proc = scriptkit.run_script_full(POLICY, NAME, repo, json.dumps(payload))
    return proc.returncode, json.loads(proc.stdout) if proc.stdout else {}, proc.stderr


def keys(document: dict) -> list[str]:
    return [item["key"] for item in document["findings"]]


def test_a_missing_allowlist_is_none_and_a_manifest_change_warns_naming_what_was_not_checked(tmp_path: Path) -> None:
    bare = scriptkit.init_repo(tmp_path / "bare", {"README.md": "x\n"})
    assert mod.load_allowlist(bare) is None
    code, document, err = run(bare, {"requirements.txt": "requests\n", "sub\\package.json": "{}", "README.md": "y\n"})
    assert (code, document) == (4, {})
    assert err.startswith(f"dependency-manifests: {ALLOWLIST} does not exist, so the dependencies named in ")
    assert "requirements.txt, sub/package.json were not checked" in err
    assert "README.md" not in err
    assert "--seed" in err


def test_a_missing_allowlist_is_silent_on_a_change_that_touches_no_manifest(tmp_path: Path) -> None:
    bare = scriptkit.init_repo(tmp_path / "bare", {"README.md": "x\n"})
    assert run(bare, {"README.md": "y\n", "src/app.py": "import requests\n"}) == (0, {}, "")


@pytest.mark.parametrize("text", ["", "# nothing approved yet\n", "\n\n"])
def test_an_allowlist_that_exists_but_lists_nothing_still_refuses(tmp_path: Path, text: str) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {ALLOWLIST: text})
    assert mod.load_allowlist(root) == []
    code, document, _ = run(root, {"requirements.txt": "requests\n"})
    assert (code, keys(document)) == (1, ["py|requests"])


def test_a_dangling_symlink_at_the_allowlist_path_is_an_unreadable_allowlist_not_a_missing_one(tmp_path: Path) -> None:
    root = scriptkit.init_repo(tmp_path / "r", {"README.md": "x\n"})
    (root / ".chock").mkdir()
    (root / ALLOWLIST).symlink_to("nowhere.txt")
    assert mod.load_allowlist(root) == []
    code, document, _ = run(root, {"requirements.txt": "requests\n"})
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
