"""verify-mcp-allowlist: the gate through chock's runner (baseline, rug pull, who may grow the allowlist) and as a process."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest
from policies import gatekit, mcpkit, scriptkit

mod = mcpkit.gate()
allowlist = mod.allowlist
FS, EVIL = mcpkit.FS, mcpkit.EVIL
ALLOW = ".chock/mcp-allowlist.json"
ONE = mcpkit.allowlist_text(mcpkit.FS_ALLOWED)
TWO = mcpkit.allowlist_text(mcpkit.FS_ALLOWED, mcpkit.REMOTE_ALLOWED)
CRASH = ("traceback (most recent call last)", "syntax error", "syntaxerror", "unexpected eof")


@pytest.fixture(autouse=True)
def person(monkeypatch: pytest.MonkeyPatch) -> None:
    """A commit is a person's here; the agent-commit cases call the gate with that event instead."""
    for name in ("CLAUDECODE", "AI_AGENT", "CHOCK_AGENT_COMMIT"):
        monkeypatch.delenv(name, raising=False)


def engine(repo: Path, writes: dict[str, str], event: str = gatekit.COMMIT) -> int:
    """The runner's exit code; a commit stages the files, the turn's end finds them on disk, tool use gets them as text."""
    if event != gatekit.PRE_TOOL_USE:
        scriptkit.write(repo, writes)
    if event == gatekit.COMMIT:
        scriptkit.git(repo, "add", "-A")
    return gatekit.judge(mcpkit.POLICY, repo, event, writes)[0]


def held(tmp_path: Path, servers: dict | None = None, allow: str | None = ONE) -> Path:
    files = {".mcp.json": mcpkit.mcp(servers)} if servers is not None else {}
    return mcpkit.repo_with(tmp_path, head={**files, **({ALLOW: allow} if allow is not None else {})})


EVENTS = [gatekit.COMMIT, gatekit.STOP, gatekit.PRE_TOOL_USE]


@pytest.mark.parametrize("event", EVENTS)
def test_a_server_added_beside_an_old_unlisted_one_is_the_only_one_judged(tmp_path: Path, event: str) -> None:
    repo = held(tmp_path, {"evil": EVIL})
    assert engine(repo, {".mcp.json": mcpkit.mcp({"evil": EVIL})}, event) == 0
    assert engine(repo, {".mcp.json": mcpkit.mcp({"evil": EVIL, "filesystem": FS})}, event) == 0
    worse = {"command": "npx", "args": ["-y", "worse"]}
    assert engine(repo, {".mcp.json": mcpkit.mcp({"evil": EVIL, "worse": worse})}, event) == 1


def word(repo: Path, writes: dict[str, str], event: str) -> str:
    """allow, warn or block: a warning exits 4 at tool use and 0 with its words at a commit."""
    if event != gatekit.PRE_TOOL_USE:
        scriptkit.write(repo, writes)
    if event == gatekit.COMMIT:
        scriptkit.git(repo, "add", "-A")
    code, err = gatekit.judge(mcpkit.POLICY, repo, event, writes)
    return "block" if code == 1 else "warn" if code == gatekit.runner.EXIT_WARN or err.strip() else "allow"


@pytest.mark.parametrize("event", EVENTS)
def test_a_changed_entry_of_an_approved_server_is_a_new_finding(tmp_path: Path, event: str) -> None:
    repo = held(tmp_path, {"filesystem": FS})
    assert word(repo, {".mcp.json": mcpkit.mcp({"filesystem": FS})}, event) == "allow"
    for change in (
        {**FS, "args": [*mcpkit.FS_ARGS, "/"]},
        {**FS, "args": [*mcpkit.FS_ARGS[:2], "/other"]},
        {"command": "uvx", "args": ["evil==1.0"]},
        {"url": "https://evil.invalid/mcp"},
    ):
        assert word(repo, {".mcp.json": mcpkit.mcp({"filesystem": change})}, event) == "block", change


@pytest.mark.parametrize("event", EVENTS)
def test_a_changed_environment_of_an_approved_server_is_observed(tmp_path: Path, event: str) -> None:
    repo = held(tmp_path, {"filesystem": FS})
    for env in ({"NODE_OPTIONS": "--require ./x.js"}, {"API_TOKEN": "literal"}):
        assert word(repo, {".mcp.json": mcpkit.mcp({"filesystem": {**FS, "env": env}})}, event) == "warn", env


def test_a_changed_unlisted_legacy_server_is_new_but_a_reformat_is_not(tmp_path: Path) -> None:
    repo = held(tmp_path, {"evil": EVIL, "filesystem": FS})
    spaced = json.dumps({"mcpServers": {"filesystem": FS, "evil": EVIL}}, indent=4)
    assert engine(repo, {".mcp.json": spaced}) == 0
    flagged = {**EVIL, "args": [*EVIL["args"], "--flag"]}
    assert engine(repo, {".mcp.json": mcpkit.mcp({"evil": flagged})}) == 1


def test_a_renamed_server_is_judged_by_its_new_name(tmp_path: Path) -> None:
    repo = held(tmp_path, {"filesystem": FS})
    assert engine(repo, {".mcp.json": mcpkit.mcp({"fs2": FS})}) == 1


def test_a_server_declared_twice_holds_one_more_copy(tmp_path: Path) -> None:
    repo = held(tmp_path, {"evil": EVIL})
    twice = json.dumps({"mcpServers": {"evil": EVIL}, "servers": {"evil": EVIL}})
    assert engine(repo, {".mcp.json": twice}) == 1


def test_the_baseline_at_tool_use_is_the_file_on_disk_not_head(tmp_path: Path) -> None:
    repo = held(tmp_path, {"filesystem": FS})
    scriptkit.write(repo, {".mcp.json": mcpkit.mcp({"evil": EVIL})})
    both = {".mcp.json": mcpkit.mcp({"evil": EVIL, "filesystem": FS})}
    assert gatekit.judge(mcpkit.POLICY, repo, gatekit.PRE_TOOL_USE, both)[0] == 0
    assert engine(repo, both, gatekit.COMMIT) == 1


def test_a_new_config_file_is_judged_whole(tmp_path: Path) -> None:
    repo = held(tmp_path)
    assert engine(repo, {".cursor/mcp.json": mcpkit.mcp({"evil": EVIL})}, gatekit.PRE_TOOL_USE) == 1
    assert engine(repo, {".cursor/mcp.json": mcpkit.mcp({"filesystem": FS})}, gatekit.PRE_TOOL_USE) == 0


def test_a_head_that_cannot_be_read_grandfathers_nothing(tmp_path: Path) -> None:
    repo = mcpkit.repo_with(tmp_path, head={".mcp.json": "{", ALLOW: ONE})
    assert engine(repo, {".mcp.json": mcpkit.mcp({"evil": EVIL})}) == 1
    assert engine(repo, {".mcp.json": "{"}) == 0
    assert engine(repo, {".mcp.json": "{ "}) == 1


def test_the_refusal_names_the_file_and_server_not_the_launch_line(tmp_path: Path) -> None:
    repo = held(tmp_path)
    secret = {"command": "npx", "args": ["-y", "evil@latest", "--token", "SECRET-VALUE-123"]}
    code, err = gatekit.judge(mcpkit.POLICY, repo, gatekit.PRE_TOOL_USE, {".mcp.json": mcpkit.mcp({"evil": secret})})
    assert code == 1
    assert ".mcp.json" in err
    assert "'evil'" in err
    assert "SECRET" not in err


def test_the_policy_approves_the_listed_pinned_server_through_the_runner(tmp_path: Path) -> None:
    repo = held(tmp_path)
    written = {".mcp.json": mcpkit.mcp({"filesystem": FS})}
    assert gatekit.judge(mcpkit.POLICY, repo, gatekit.PRE_TOOL_USE, written) == (0, "")
    assert gatekit.judge(mcpkit.POLICY, repo, gatekit.STOP, written)[0] == 0


@pytest.mark.parametrize("event", ["tool_use", "stop", "agent-commit"])
def test_an_agent_is_judged_by_the_allowlist_head_holds(tmp_path: Path, event: str) -> None:
    repo = held(tmp_path, allow=ONE)
    scriptkit.write(repo, {ALLOW: TWO})
    docs = mcpkit.mcp({"docs": {"url": "https://mcp.example.invalid/mcp"}})
    items = mod.findings({"event": event, "repo_root": str(repo), "writes": {".mcp.json": docs}})
    assert [i["key"].split("|")[0] for i in items] == ["allowlist"]


@pytest.mark.parametrize("event", ["commit", "push", "ci", ""])
def test_a_person_s_commit_is_judged_by_the_allowlist_on_disk(tmp_path: Path, event: str) -> None:
    repo = held(tmp_path, allow=ONE)
    scriptkit.write(repo, {ALLOW: TWO})
    docs = mcpkit.mcp({"docs": {"url": "https://mcp.example.invalid/mcp"}})
    assert mod.findings({"event": event, "repo_root": str(repo), "writes": {".mcp.json": docs}}) == []


def test_a_person_may_add_the_server_and_its_allowlist_entry_in_one_commit(tmp_path: Path) -> None:
    repo = held(tmp_path, allow=ONE)
    writes = {ALLOW: TWO, ".mcp.json": mcpkit.mcp({"docs": {"url": "https://mcp.example.invalid/mcp"}})}
    assert engine(repo, writes) == 0


def test_a_missing_allowlist_is_an_empty_one(tmp_path: Path) -> None:
    repo = held(tmp_path, allow=None)
    assert engine(repo, {".mcp.json": mcpkit.mcp({"filesystem": FS})}) == 1
    assert engine(repo, {".cursor/mcp.json": mcpkit.mcp({"filesystem": FS})}, gatekit.PRE_TOOL_USE) == 1


def test_a_repo_with_no_commit_has_an_empty_allowlist_for_an_agent(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "bare")
    scriptkit.write(repo, {ALLOW: ONE})
    written = {".mcp.json": mcpkit.mcp({"filesystem": FS})}
    assert len(mod.findings({"event": "tool_use", "repo_root": str(repo), "writes": written})) == 1
    assert mod.findings({"event": "commit", "repo_root": str(repo), "writes": written}) == []


@pytest.mark.parametrize("event", ["tool_use", "stop", "agent-commit"])
def test_an_agent_cannot_grow_the_allowlist(tmp_path: Path, event: str) -> None:
    repo = held(tmp_path, allow=ONE)
    items = mod.findings({"event": event, "repo_root": str(repo), "writes": {ALLOW: TWO}})
    assert [i["key"].split("|")[:2] for i in items] == [["allowlist-entry", "filesystem"], ["allowlist-entry", "docs"]]
    assert "only a person approves" in items[0]["message"]


def test_the_allowlist_may_shrink_or_stay_and_a_person_may_grow_it(tmp_path: Path) -> None:
    repo = held(tmp_path, allow=TWO)
    assert engine(repo, {ALLOW: ONE}, gatekit.PRE_TOOL_USE) == 0
    assert engine(repo, {ALLOW: TWO}, gatekit.PRE_TOOL_USE) == 0
    assert engine(repo, {ALLOW: mcpkit.allowlist_text()}, gatekit.PRE_TOOL_USE) == 0
    grown = mcpkit.allowlist_text(
        mcpkit.FS_ALLOWED, mcpkit.REMOTE_ALLOWED, {"name": "new", "launcher": "uvx", "spec": "p==1.0"}
    )
    assert engine(repo, {ALLOW: grown}, gatekit.PRE_TOOL_USE) == 1
    assert engine(repo, {ALLOW: grown}) == 0


def test_an_edited_allowlist_entry_is_a_new_entry(tmp_path: Path) -> None:
    repo = held(tmp_path, allow=ONE)
    edited = mcpkit.allowlist_text({**mcpkit.FS_ALLOWED, "spec": mcpkit.FS_ALLOWED["spec"] + " /"})
    assert engine(repo, {ALLOW: edited}, gatekit.PRE_TOOL_USE) == 1
    host = mcpkit.allowlist_text({"name": "docs", "url_host": "*.example.invalid"})
    assert engine(held(tmp_path / "h", allow=host), {ALLOW: host}, gatekit.PRE_TOOL_USE) == 0


def test_removing_an_entry_leaves_an_old_server_alone_but_not_a_new_one(tmp_path: Path) -> None:
    repo = held(tmp_path, {"filesystem": FS}, allow=ONE)
    assert engine(repo, {ALLOW: mcpkit.allowlist_text()}) == 0
    assert engine(repo, {ALLOW: mcpkit.allowlist_text(), ".cursor/mcp.json": mcpkit.mcp({"filesystem": FS})}) == 1


@pytest.mark.parametrize("path", [ALLOW, ".CHOCK/MCP-Allowlist.json", "sub\\.chock\\mcp-allowlist.json"])
def test_the_allowlist_path_is_matched_in_any_case_and_slash(tmp_path: Path, path: str) -> None:
    repo = held(tmp_path, allow=ONE)
    assert len(mod.findings({"event": "tool_use", "repo_root": str(repo), "writes": {path: TWO}})) == 2


BAD_LISTS = [
    ("not json", "not valid JSON"),
    ("[]", "one object"),
    ('{"servers": [], "extra": 1}', "one object"),
    ("{}", "one object"),
    ('{"servers": [], "servers": []}', "no repeated key"),
    ('{"servers": 3}', "list of at most"),
    ('{"servers": ["x"]}', "an object of text"),
    ('{"servers": [{"name": "a", "launcher": "npx", "spec": "x", "extra": "y"}]}', "an object of text"),
    ('{"servers": [{"name": "a", "launcher": 3}]}', "an object of text"),
    ('{"servers": [{"launcher": "npx"}]}', "needs a name"),
    ('{"servers": [{"name": "a"}]}', "needs a name"),
    ('{"servers": [{"name": "a", "launcher": "npx", "url_host": "x.example"}]}', "needs a name"),
    ('{"servers": [{"name": "a", "spec": "x", "url_host": "x.example"}]}', "needs a name"),
    ('{"servers": [{"name": "a", "url_host": "*"}]}', "url_host"),
    ('{"servers": [{"name": "a", "url_host": "https://x.example/"}]}', "url_host"),
    ('{"servers": [{"name": "a", "url_host": "*.com"}]}', "url_host"),
]


@pytest.mark.parametrize(("text", "why"), BAD_LISTS)
def test_an_allowlist_that_is_not_the_closed_schema_is_refused(text: str, why: str) -> None:
    with pytest.raises(allowlist.AllowlistError, match=why):
        allowlist.parse(text)


def test_the_allowlist_may_carry_comments_and_a_remote_and_a_local_entry() -> None:
    text = '// approved 2026-10-02\n{"servers": [{"name": "a", "launcher": "npx"}, {"name": "b", "url_host": "*.example.invalid"},]}'
    entries = allowlist.parse(text)
    assert [(e.name, e.launcher, e.spec, e.host is None) for e in entries] == [
        ("a", "npx", "", True),
        ("b", "", "", False),
    ]


def test_too_many_entries_are_refused() -> None:
    many = {"servers": [{"name": f"s{i}", "launcher": "npx", "spec": "x"} for i in range(allowlist.MAX_ENTRIES + 1)]}
    with pytest.raises(allowlist.AllowlistError, match="at most"):
        allowlist.parse(json.dumps(many))


@pytest.mark.parametrize(("text", "why"), BAD_LISTS[:4])
def test_an_unreadable_allowlist_leaves_every_server_unlisted_and_says_so(tmp_path: Path, text: str, why: str) -> None:
    repo = held(tmp_path, allow=text)
    written = {".mcp.json": mcpkit.mcp({"filesystem": FS})}
    for event in ("commit", "tool_use"):
        items = mod.findings({"event": event, "repo_root": str(repo), "writes": written})
        assert [i["key"].split("|")[0] for i in items] == ["allowlist-unreadable", "allowlist"]
        assert why in items[0]["message"]
    assert engine(repo, written) == 1
    unrelated = {"README.md": "x\n"}
    assert mod.findings({"event": "commit", "repo_root": str(repo), "writes": unrelated}) == []


def test_an_agent_that_writes_a_broken_allowlist_is_refused(tmp_path: Path) -> None:
    repo = held(tmp_path, allow=ONE)
    items = mod.findings({"event": "tool_use", "repo_root": str(repo), "writes": {ALLOW: "{"}})
    assert [i["key"].split("|")[0] for i in items] == ["allowlist-unreadable"]


def test_an_allowlist_that_cannot_be_read_from_disk_is_refused(tmp_path: Path) -> None:
    repo = held(tmp_path, allow=None)
    (repo / ALLOW).mkdir(parents=True)
    items = mod.findings(
        {"event": "commit", "repo_root": str(repo), "writes": {".mcp.json": mcpkit.mcp({"filesystem": FS})}}
    )
    assert items[0]["key"].startswith("allowlist-unreadable|")
    assert "unreadable" in items[0]["message"]


def test_a_head_allowlist_that_is_too_large_or_cannot_be_asked_for_counts_as_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = held(tmp_path, allow=ONE)
    written = {".mcp.json": mcpkit.mcp({"filesystem": FS})}
    assert mod.findings({"event": "tool_use", "repo_root": str(repo), "writes": written}) == []
    monkeypatch.setattr(allowlist, "LIMIT", 10)
    assert len(mod.findings({"event": "tool_use", "repo_root": str(repo), "writes": written})) == 1
    monkeypatch.setattr(allowlist, "LIMIT", 1 << 20)
    monkeypatch.setattr(allowlist, "GIT", str(tmp_path / "no-such-git"))
    assert len(mod.findings({"event": "tool_use", "repo_root": str(repo), "writes": written})) == 1

    def slow(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired("git", 20)

    monkeypatch.setattr(allowlist, "GIT", "git")
    monkeypatch.setattr(allowlist.subprocess, "run", slow)
    assert len(mod.findings({"event": "tool_use", "repo_root": str(repo), "writes": written})) == 1


def test_a_missing_repo_root_means_the_current_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = held(tmp_path, allow=ONE)
    monkeypatch.chdir(repo)
    written = {".mcp.json": mcpkit.mcp({"filesystem": FS})}
    assert mod.findings({"event": "commit", "writes": written}) == []
    assert mod.findings({"writes": written}) == []
    assert mod.findings({}) == []


def run(repo: Path, writes: dict[str, str], event: str = "commit") -> tuple[int, str, str]:
    proc = scriptkit.run_script_full(
        mcpkit.POLICY, mcpkit.GATE_FILE, repo, json.dumps({"event": event, "repo_root": str(repo), "writes": writes})
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_the_script_run_as_a_process_refuses_and_allows(tmp_path: Path) -> None:
    repo = held(tmp_path)
    code, out, err = run(repo, {".mcp.json": mcpkit.mcp({"evil": EVIL})})
    assert code == 1
    assert json.loads(out)["findings"]
    assert err.startswith("verify-mcp-allowlist: MCP server config refused")
    assert "allowlist" in err
    assert not any(marker in err.lower() for marker in CRASH)
    assert run(repo, {".mcp.json": mcpkit.mcp({"filesystem": FS})}) == (0, '{"findings": []}\n', "")
    assert run(repo, {"a.txt": "x"})[0] == 0


def test_a_fault_exits_two_and_says_so(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert mod.main() == 2
    err = capsys.readouterr().err
    assert "internal error" in err
    assert not any(marker in err.lower() for marker in CRASH)


def test_a_rule_that_is_new_in_v2_warns_and_a_v1_tier_refuses(tmp_path: Path) -> None:
    loose = {"name": "loose", "launcher": "npx", "spec": "-y loose-mcp"}
    repo = held(tmp_path, allow=mcpkit.allowlist_text(mcpkit.FS_ALLOWED, loose))
    observed = {".mcp.json": mcpkit.mcp({"loose": {"command": "npx", "args": ["-y", "loose-mcp"]}})}
    code, out, err = run(repo, observed)
    assert code == mod.WARN_EXIT == 4
    assert json.loads(out)["findings"][0]["key"].startswith("unpinned|")
    assert err.startswith("verify-mcp-allowlist: MCP server config findings (observed")
    both = {".mcp.json": mcpkit.mcp({"loose": observed_server(), "evil": EVIL})}
    code, _, err = run(repo, both)
    assert code == 1
    assert err.startswith("verify-mcp-allowlist: MCP server config refused")
    assert {"allowlist", "allowlist-entry", "allowlist-unreadable", "unreadable", "unreadable-entry"} == mod.ENFORCED


def observed_server() -> dict:
    return {"command": "npx", "args": ["-y", "loose-mcp"]}


def test_every_new_rule_is_observed_and_none_is_enforced_by_accident(tmp_path: Path) -> None:
    repo = held(tmp_path)
    classes = {
        "unpinned": {"command": "npx", "args": ["-y", "p"]},
        "inline": {"command": "bash", "args": ["-c", "echo hi"]},
        "url": {"url": "http://a.example.invalid/"},
        "secret": {"command": "npx", "args": ["p@1.0.0"], "env": {"API_KEY": "lit"}},
        "option": {"command": "npx", "args": ["p@1.0.0", "--allow-all"]},
        "floor": {"command": "npx", "args": ["mcp-remote@0.0.1"]},
        "no-source": {"source": "extension"},
    }
    seen = {
        i["key"].split("|")[0]
        for name, cfg in classes.items()
        for i in mod.findings(
            {"event": "commit", "repo_root": str(repo), "writes": {".mcp.json": mcpkit.mcp({name: cfg})}}
        )
    }
    assert set(classes) <= seen
    assert not (seen - {"allowlist"}) & mod.ENFORCED
