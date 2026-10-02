"""registry-config: the gate's document, exit codes, host table, repository allowlist and engine wiring."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from policies import gatekit, scriptkit
from policies.test_registry_config import B_HTTP, B_SCRIPTS, B_TLS, B_UNREAD, LIT, MODULES, NAME, mod, rules

reg_core = MODULES["reg_core"]
reg_hosts = MODULES["reg_hosts"]

POLICY = "registry-config"
EVIL_NPMRC = "min-release-age=3\nregistry=https://npm.corp.example/\n"


def run_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stdin: str) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = mod.main()
    out = capsys.readouterr()
    return code, out.out, out.err


def payload(writes: dict[str, str], root: str = "/nonexistent") -> str:
    return json.dumps({"event": "commit", "repo_root": root, "writes": writes})


@pytest.mark.parametrize(
    ("writes", "code"),
    [
        ({"README.md": "strict-ssl=false\n"}, 0),
        ({".npmrc": "strict-ssl=false\n"}, 1),
        ({"pnpm-workspace.yaml": "packages: [a]\n"}, 3),
        ({"x.txt": 5, ".npmrc": "min-release-age=1\n"}, 0),
    ],
)
def test_exit_code_follows_the_strictest_finding(monkeypatch, capsys, writes: dict, code: int) -> None:
    got, out, err = run_main(monkeypatch, capsys, payload(writes))
    assert got == code
    assert "findings" in json.loads(out)
    assert ("registry-config:" in err) == (code != 0)


@pytest.mark.parametrize("stdin", ["not json", "[]", json.dumps({"writes": []})])
def test_a_payload_that_is_not_the_gate_json_is_a_fault(monkeypatch, capsys, stdin: str) -> None:
    code, _, err = run_main(monkeypatch, capsys, stdin)
    assert code == 2
    assert "cannot judge" in err


def test_a_broken_host_table_is_a_fault_never_an_allow(monkeypatch, capsys, tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    table = json.loads(reg_hosts.TABLE.read_text(encoding="utf-8"))
    table["hosts"] = {"npm": ["*"], "pypi": [], "go": "x"}
    (data / "registry-hosts.json").write_text(json.dumps(table), encoding="utf-8")
    monkeypatch.setattr(reg_hosts, "TABLE", data / "registry-hosts.json")
    code, _, err = run_main(monkeypatch, capsys, payload({".npmrc": "x=1\n"}))
    assert code == 2
    assert "host table" in err


def test_the_shipped_table_holds_the_default_registries() -> None:
    hosts = {entry.host.name for entry in reg_hosts.table()}
    assert {"registry.npmjs.org", "pypi.org", "index.crates.io", "api.nuget.org", "proxy.golang.org"} <= hosts
    assert not {"github.com", "test.pypi.org"} & hosts


def test_too_many_findings_become_one_new_finding(monkeypatch, capsys) -> None:
    text = "".join(f"@s{i}:registry=http://r{i}.example/\n" for i in range(mod.MAX_FINDINGS + 1))
    code, out, _ = run_main(monkeypatch, capsys, payload({".npmrc": text}))
    found = json.loads(out)["findings"]
    assert code == 1
    assert [(f["key"], f["new"]) for f in found] == [("too-many", True)]


def test_an_oversized_config_is_refused_unread() -> None:
    assert rules(".npmrc", "#" * (mod.MAX_TEXT + 1)) == [B_UNREAD]


def test_a_credential_is_keyed_by_digest_and_never_echoed() -> None:
    found = mod.findings({"repo_root": ".", "writes": {".pypirc": f"[pypi]\npassword = {LIT}\n"}})
    assert all(LIT not in f["key"] and LIT not in f["message"] for f in found)


def test_keys_carry_no_line_number_so_a_moved_line_is_the_same_finding() -> None:
    one = mod.findings({"writes": {".npmrc": "strict-ssl=false\n"}})
    two = mod.findings({"writes": {".npmrc": "\n\n# moved\nstrict-ssl=false\n"}})
    assert [f["key"] for f in one] == [f["key"] for f in two]
    assert [f["line"] for f in one] != [f["line"] for f in two]


def committed_repo(tmp_path: Path, allowlist: str | None) -> Path:
    files = {"README.md": "x\n"} | ({reg_hosts.REPO_LIST: allowlist} if allowlist is not None else {})
    return scriptkit.init_repo(tmp_path / "repo", files)


@pytest.mark.parametrize(
    ("allowlist", "disk", "want"),
    [
        ("npm.corp.example\n", None, []),
        ("*.corp.example\n", None, []),
        ("corp.example\n", None, ["reg-registry-host"]),
        ("not a host!\n", None, ["reg-registry-host"]),
        (None, "npm.corp.example\n", ["reg-registry-host"]),
        ("other.example\n", "npm.corp.example\n", ["reg-registry-host"]),
    ],
)
def test_the_repository_allowlist_is_read_from_head_never_the_working_tree(
    tmp_path: Path, allowlist: str | None, disk: str | None, want: list[str]
) -> None:
    repo = committed_repo(tmp_path, allowlist)
    if disk is not None:
        scriptkit.write(repo, {reg_hosts.REPO_LIST: disk})
    found = mod.findings({"repo_root": str(repo), "writes": {".npmrc": EVIL_NPMRC}})
    assert [f["rule"] for f in found] == want


def test_a_written_allowlist_asks_and_is_used_for_the_same_write(tmp_path: Path) -> None:
    writes = {"./.chock/Registry-Hosts.txt": "npm.corp.example\n", ".npmrc": EVIL_NPMRC}
    found = mod.findings({"repo_root": str(tmp_path), "writes": writes})
    assert [f["rule"] for f in found] == ["reg-allowlist-changed"]


def test_git_that_cannot_run_allows_nothing_extra(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(reg_hosts.subprocess, "run", boom)
    assert reg_hosts.committed(".") == ""


def test_loopback_hosts_are_local() -> None:
    hosts = ("localhost", "a.localhost", "127.0.0.2", "[::1]", "localhost.example", "10.0.0.1", "[2001:db8::1]")
    found = [reg_core.loopback(reg_core.parse_url(f"http://{h}/").host) for h in hosts]
    assert found == [True, True, True, True, False, False, False]


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        (".npmrc", "strict-ssl=false\nmin-release-age=1\n", [B_TLS]),
        (".yarnrc.yml", "enableScripts: true\nnpmMinimalAgeGate: 1\n", [B_SCRIPTS]),
        ("bunfig.toml", "[install\n", [B_UNREAD]),
        ("bunfig.toml", '[install.registry]\nusername = "u"\n[install]\nminimumReleaseAge = 1\n', []),
        (".condarc", "ssl_verify: false\n", [B_TLS]),
        ("composer.json", '{"config": {"secure-http": false}}', [B_TLS]),
        (
            ".github/dependabot.yml",
            "updates:\n  - insecure-external-code-execution: allow\n    cooldown: {}\n",
            [B_SCRIPTS],
        ),
        (
            ".cargo/config.toml",
            '[source.crates-io]\nreplace-with = "v"\n[source.v]\ngit = "https://g.example/r"\n',
            ["reg-overrides-redirect"],
        ),
        ("Dockerfile", "ENV GOINSECURE=x\nENV GOSUMDB=off\nENV GOFLAGS=-insecure\n", [B_TLS]),
        ("Dockerfile", "ENV GOPROXY=http://p.example\n", [B_HTTP]),
    ],
)
def test_each_remaining_setting_shape(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == want


@pytest.mark.parametrize(
    ("event", "writes", "code"),
    [
        (gatekit.COMMIT, {".npmrc": "strict-ssl=false\n"}, 1),
        (gatekit.PRE_TOOL_USE, {".npmrc": "strict-ssl=false\n"}, 1),
        (gatekit.PRE_TOOL_USE, {"README.md": "strict-ssl=false\n"}, 0),
    ],
)
def test_the_engine_runs_the_declared_gate(tmp_path: Path, event: str, writes: dict, code: int) -> None:
    repo = scriptkit.init_repo(tmp_path / "repo", {"README.md": "x\n"})
    if event == gatekit.COMMIT:
        scriptkit.write(repo, writes)
        scriptkit.git(repo, "add", "-A")
    got, _ = gatekit.judge(POLICY, repo, event, writes=writes)
    assert got == code


def test_the_manifest_declares_a_blocking_script_gate() -> None:
    gate = scriptkit.manifest(POLICY)["hook"]["gate"]
    assert (gate["kind"], gate["action"], gate["params"]["script"]) == ("script", "block", NAME)
    assert sorted(gate["on"]) == ["commit", "tool_use"]


def test_the_shipped_script_runs_as_a_program() -> None:
    script = scriptkit.script_path(POLICY, NAME)
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=payload({".npmrc": "strict-ssl=false\n"}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert [f["rule"] for f in json.loads(proc.stdout)["findings"]] == [B_TLS, "reg-cooldown-absent"]
