"""verify-mcp-allowlist: who may grow the allowlist, the closed schema, and where each event reads it from."""

from __future__ import annotations

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


def test_a_missing_allowlist_file_is_an_empty_list_for_a_person_and_an_agent(tmp_path: Path) -> None:
    repo = held(tmp_path, allow=None)
    assert allowlist.load(repo, "commit") == ((), None)
    assert allowlist.load(repo, "tool_use") == ((), None)
