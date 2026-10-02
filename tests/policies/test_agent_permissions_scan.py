"""agent-permissions-scan: the script gate -- findings, baselines, waivers, exit codes and the engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import gatekit, scriptkit
from policies.permskit import CLAUDE, NAME, POLICY, keys, mod, payload, sidecar


def settings(**permissions: object) -> str:
    return json.dumps({"permissions": permissions}, indent=2)


@pytest.fixture(autouse=True)
def person(monkeypatch: pytest.MonkeyPatch) -> None:
    """Judge as a person's shell by default; a test that needs an agent sets the marker itself."""
    for name in mod.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"README.md": "x\n"})


def held(tmp_path: Path, files: dict[str, str]) -> Path:
    return scriptkit.init_repo(tmp_path / "h", files)


# --- the script ----------------------------------------------------------------------------------------------


def test_the_manifest_declares_a_script_gate_that_only_warns() -> None:
    manifest = scriptkit.manifest(POLICY)
    gate = manifest["hook"]["gate"]
    assert (gate["kind"], gate["on"], gate["action"], gate["params"]) == (
        "script",
        ["commit", "tool_use"],
        "warn",
        {"script": NAME},
    )
    assert (manifest["artifact"], manifest["enforcement"]) == ("rule", "advise")
    assert len(manifest["description"]) <= 500


def test_a_clean_scoped_config_has_no_findings(repo: Path) -> None:
    writes = {CLAUDE: settings(allow=["Read", "Bash(npm test:*)", "WebFetch(domain:example.com)"], deny=["Read(.env)"])}
    assert mod.findings(payload(repo, writes)) == []
    assert (
        mod.findings(
            payload(
                repo,
                {
                    "package.json": json.dumps(dict(allow=["*"])),
                    "notes.md": "defaultMode: bypassPermissions",
                },
            )
        )
        == []
    )


def test_findings_are_keyed_by_rule_path_and_value_and_never_by_line(repo: Path) -> None:
    text = json.dumps({"permissions": dict(allow=["Read", "*"])}, indent=2) + "\n"
    (found,) = mod.findings(payload(repo, {CLAUDE: text}))
    assert found["key"] == "ap-allow-broad|permissions.allow|*"
    assert (found["path"], found["line"], found["new"]) == (CLAUDE, 5, False)
    shifted = mod.findings(payload(repo, {CLAUDE: "\n\n" + text.replace('"Read",', '"Read", "Grep",')}))
    assert [f["key"] for f in shifted] == [found["key"]]


def test_a_value_escaped_in_the_text_still_gets_a_line(repo: Path) -> None:
    (found,) = mod.findings(payload(repo, {CLAUDE: '{\n"\\u0064efaultMode": "bypassPermissions"}'}))
    assert (found["key"], found["line"]) == ("ap-mode-bypass|defaultMode|bypassPermissions", 2)
    (other,) = mod.findings(payload(repo, {CLAUDE: '{\n"defaultMode": "\\u0062ypassPermissions"}'}))
    assert other["line"] == 2


def test_an_unreadable_config_is_one_finding_keyed_by_its_text(repo: Path) -> None:
    (found,) = mod.findings(payload(repo, {CLAUDE: '{"permissions": '}))
    assert found["key"].startswith("ap-unreadable|<file>|")
    assert "cannot be read" in found["message"]
    other = mod.findings(payload(repo, {CLAUDE: '{"permissions": }'}))
    assert other[0]["key"] != found["key"]


def test_duplicate_keys_are_judged_in_either_order(repo: Path) -> None:
    bypass_last = '{"permissions": {"defaultMode": "default", "defaultMode": "auto"}}'
    bypass_first = '{"permissions": {"defaultMode": "auto", "defaultMode": "default"}}'
    assert keys(repo, {CLAUDE: bypass_last}) == ["ap-mode-bypass|permissions.defaultMode|auto"]
    assert keys(repo, {CLAUDE: bypass_first}) == ["ap-mode-bypass|permissions.defaultMode|auto"]
    assert keys(repo, {CLAUDE: '{"permissions": {"defaultMode": "default", "defaultMode": "plan"}}'}) == []


def test_comments_and_trailing_commas_do_not_hide_a_grant(repo: Path) -> None:
    text = '// team settings\n{\n  /* shell */\n  "permissions": {"allow": [\n    "Bash", // everything\n  ],},\n}\n'
    assert keys(repo, {CLAUDE: text}) == ["ap-allow-broad|permissions.allow|Bash"]


def test_every_surface_is_read(repo: Path) -> None:
    writes = {
        ".codex/config.toml": 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',
        ".gemini/settings.json": '{"general": {"defaultApprovalMode": "yolo"}}',
        ".vscode/settings.json": '{"chat.tools.terminal.autoApprove": {"/.*/": true}}',
        ".aider.conf.yml": "yes-always: true\n",
        ".continue/config.yaml": "defaultMode: bypassPermissions\n",
        ".cursor/cli.json": '{"permissions": {"allow": ["Shell(*)"]}}',
        "opencode.json": '{"permission": {"bash": "allow"}}',
    }
    found = {f["path"] for f in mod.findings(payload(repo, writes))}
    assert found == set(writes)


def test_baseline_runs_skip_the_deny_comparison(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(deny=["Read(.env)"])})
    assert keys(base, {CLAUDE: settings(allow=["Read"])}) == ["ap-deny-removed|permissions.deny|Read(.env)"]
    assert keys(base, {CLAUDE: settings(allow=["Read"])}, baseline=True) == []


def test_a_removed_deny_entry_is_always_new_and_a_kept_one_is_not(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)", "Bash(rm:*)"])})
    (gone,) = mod.findings(
        payload(base, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)", "Bash(rm:*)", "Edit"])})
        | {"writes": {CLAUDE: settings(deny=["Bash(rm:*)", "Bash(rm:*)"])}}
    )
    assert (gone["key"], gone["new"], gone["line"]) == ("ap-deny-removed|permissions.deny|Read(.env)", True, 1)
    assert keys(base, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)", "Bash(rm:*)"], allow=["Read"])}) == []
    assert keys(base, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)"])}) == [
        "ap-deny-removed|permissions.deny|Bash(rm:*)"
    ]


def test_deny_shrinkage_is_read_on_disk_at_tool_use_and_ignores_unreadable_texts(tmp_path: Path) -> None:
    base = held(tmp_path, {"README.md": "x\n"})
    scriptkit.write(base, {CLAUDE: settings(deny=["Read(.env)"])})
    write = {CLAUDE: settings()}
    assert keys(base, write, "tool_use") == ["ap-deny-removed|permissions.deny|Read(.env)"]
    assert keys(base, write, "commit") == []
    scriptkit.write(base, {CLAUDE: "not json"})
    assert keys(base, write, "tool_use") == []
    (base / CLAUDE).unlink()
    assert keys(base, write, "tool_use") == []


def test_head_text_that_cannot_be_read_is_not_a_deny_baseline(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: "{ nope"})
    assert keys(base, {CLAUDE: settings(allow=["Read"])}) == []


def waiver_file(*items: dict) -> str:
    return json.dumps({"waive": list(items)})


GRANT = {CLAUDE: settings(allow=["Bash(curl:*)"])}
WAIVE = {"file": CLAUDE, "path": "permissions.allow", "value": "Bash(curl:*)"}


def test_a_waiver_in_head_clears_exactly_its_finding(tmp_path: Path) -> None:
    base = held(tmp_path, {sidecar.PATH: waiver_file(WAIVE)})
    both = {CLAUDE: settings(allow=["Bash(curl:*)", "Bash(rm:*)"])}
    for event in ("commit", "tool_use"):
        assert keys(base, GRANT, event) == []
        assert keys(base, both, event) == ["ap-allow-broad|permissions.allow|Bash(rm:*)"]
    other_file = {".claude/settings.local.json": GRANT[CLAUDE]}
    assert len(keys(base, other_file)) == 1


def test_a_person_may_add_the_waiver_in_the_commit_an_agent_may_not(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writes = {**GRANT, sidecar.PATH: waiver_file(WAIVE)}
    for name in mod.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    assert keys(repo, writes, "commit") == []
    assert len(keys(repo, writes, "tool_use")) == 2
    monkeypatch.setenv("CLAUDECODE", "1")
    assert len(keys(repo, writes, "commit")) == 2
    monkeypatch.setenv("CLAUDECODE", "0")
    assert keys(repo, writes, "commit") == []


def test_a_sidecar_that_breaks_the_schema_grants_nothing_and_is_reported(tmp_path: Path) -> None:
    bad = json.dumps({"waive": [WAIVE], "extra": True})
    base = held(tmp_path, {sidecar.PATH: bad})
    assert len(keys(base, GRANT)) == 1
    (found,) = mod.findings(payload(base, {sidecar.PATH: bad}))
    assert found["key"].startswith("ap-sidecar-invalid|")
    assert found["path"] == sidecar.PATH
    assert mod.findings(payload(base, {sidecar.PATH: waiver_file(WAIVE)})) == []
    unknown_entry = json.dumps({"waive": [{**WAIVE, "reason": "ok"}]})
    assert len(mod.findings(payload(base, {sidecar.PATH: unknown_entry}))) == 1


def test_non_text_writes_are_skipped(repo: Path) -> None:
    assert mod.findings({"event": "commit", "repo_root": str(repo), "writes": {CLAUDE: None}}) == []
    assert mod.findings({"event": "commit"}) == []


def test_person_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in mod.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    assert mod.by_person("commit")
    assert not any(mod.by_person(event) for event in ("push", "ci", "tool_use", "stop"))
    monkeypatch.setenv("AI_AGENT", "yes")
    assert not mod.by_person("commit")


# --- as a process and through the engine ---------------------------------------------------------------------


def run(repo: Path, writes: dict[str, str], event: str = "commit") -> tuple[int, str, str]:
    proc = scriptkit.run_script_full(POLICY, NAME, repo, json.dumps(payload(repo, writes, event)))
    return proc.returncode, proc.stdout, proc.stderr


def test_exit_codes_and_the_document(repo: Path) -> None:
    code, out, err = run(repo, {CLAUDE: settings(allow=["Read"])})
    assert (code, json.loads(out)) == (0, {"findings": []}) and not err
    code, out, err = run(repo, GRANT)
    assert code == 1
    assert json.loads(out)["findings"][0]["key"] == "ap-allow-broad|permissions.allow|Bash(curl:*)"
    assert "grants more than named" in err and sidecar.PATH in err and "Bash(curl:*)" in err


def test_a_fault_exits_2_and_never_reads_as_a_verdict(repo: Path) -> None:
    proc = scriptkit.run_script_full(POLICY, NAME, repo, "not json")
    assert proc.returncode == 2
    assert "could not reach a decision" in proc.stderr


def test_the_engine_warns_on_a_new_grant_and_not_on_one_already_there(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(allow=["Bash(curl:*)"])})
    scriptkit.write(base, {CLAUDE: settings(allow=["Read", "Bash(curl:*)"])})
    scriptkit.git(base, "add", "-A")
    assert gatekit.judge(POLICY, base, gatekit.COMMIT)[0] == 0
    scriptkit.write(base, {CLAUDE: settings(allow=["Read", "Bash(curl:*)", "Bash(sudo:*)"])})
    scriptkit.git(base, "add", "-A")
    _, err = gatekit.judge(POLICY, base, gatekit.COMMIT)
    assert "Bash(sudo:*)" in err and "Bash(curl:*)" not in err and "warn" in err.lower()


def test_the_engine_flags_a_removed_deny_entry_at_commit_and_at_the_turns_end(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(deny=["Read(.env)"])})
    scriptkit.write(base, {CLAUDE: settings(allow=["Read"])})
    scriptkit.git(base, "add", "-A")
    for event in (gatekit.COMMIT, gatekit.STOP):
        _, err = gatekit.judge(POLICY, base, event, {CLAUDE: settings(allow=["Read"])})
        assert "deny entry" in err


def test_an_agent_that_adds_a_waiver_is_reported_and_a_person_is_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = held(tmp_path, {sidecar.PATH: waiver_file(WAIVE)})
    both = {"file": "a.json", "path": "p", "value": "v"}
    write = {sidecar.PATH: waiver_file(WAIVE, both)}
    assert mod.findings(payload(base, write)) == []
    monkeypatch.setenv("CLAUDECODE", "1")
    for event in ("commit", "tool_use"):
        (found,) = mod.findings(payload(base, write, event))
        assert found["key"] == "ap-agent-waiver|a.json|p|v" and found["new"] is True
    assert mod.findings(payload(base, write, baseline=True)) == []
    assert mod.findings(payload(base, {sidecar.PATH: waiver_file(WAIVE)})) == []
    broken = held(tmp_path / "b", {sidecar.PATH: "{ nope"})
    assert len(mod.findings(payload(broken, write))) == 2


def test_an_opencode_deny_that_is_loosened_is_a_removal(tmp_path: Path) -> None:
    before = json.dumps({"permission": {"bash": {"rm *": "deny", "ls": "allow"}, "edit": "deny"}})
    base = held(tmp_path, {"opencode.json": before})
    after = json.dumps({"permission": {"bash": "ask", "edit": "ask"}})
    assert sorted(keys(base, {"opencode.json": after})) == [
        "ap-deny-removed|permission.bash|rm *",
        "ap-deny-removed|permission|edit",
    ]
    assert keys(base, {"opencode.json": before}) == []


def test_identical_grants_in_two_places_count_twice(tmp_path: Path) -> None:
    servers = {"mcpServers": [{"autoApprove": ["*"]}, {"autoApprove": ["*"]}]}
    one = {"mcpServers": [{"autoApprove": ["*"]}]}
    base = held(tmp_path, {".continue/config.json": json.dumps(one)})
    assert keys(base, {".continue/config.json": json.dumps(servers)}) == ["ap-allow-broad|mcpServers.autoApprove|*"] * 2
