"""protect-agent-config 0.7.0: the link follower reads Windows paths (both separators, `\\\\?\\` device prefixes) the same on any host."""

from __future__ import annotations

import ntpath
import os
import posixpath
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
reach = guardkit.load_guard(POLICY, "pathreach")
pathset = guardkit.load_guard(POLICY, "pathset")
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")
links = sys.modules["pathlink"]  # the one copy the guard and the gate import, so the disk below is the one they read

FLAVOURS = [pytest.param(ntpath, "C:\\r", id="ntpath"), pytest.param(posixpath, "/work/r", id="posixpath")]


class Disk:
    """A folder tree the follower reads instead of the real disk, under the path rules of one flavour."""

    def __init__(
        self,
        flavour: ModuleType,
        links_: dict[str, str],
        listing: dict[str, list[str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self.links = {self.key(k): v for k, v in links_.items()}
        self.listing = {self.key(k): v for k, v in listing.items()}
        path = SimpleNamespace(
            sep=flavour.sep,
            splitdrive=flavour.splitdrive,
            join=flavour.join,
            dirname=flavour.dirname,
            normpath=flavour.normpath,
            islink=lambda p: self.key(p) in self.links,
        )
        monkeypatch.setattr(links, "_path", path)
        monkeypatch.setattr(links.os, "readlink", lambda p: self.links[self.key(p)])
        monkeypatch.setattr(links.os, "listdir", lambda p: self.listing.get(self.key(p), []))

    @staticmethod
    def key(path: str) -> str:
        return path.replace("\\", "/").rstrip("/").lower()


def _native(flavour: ModuleType, root: str, *parts: str) -> str:
    return flavour.normpath(flavour.join(root, *parts))


@pytest.mark.parametrize(("flavour", "root"), FLAVOURS)
def test_a_plain_path_is_read_from_the_repository_folder_in_either_separator(
    flavour: ModuleType, root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    Disk(flavour, {}, {}, monkeypatch)
    expected = {_native(flavour, root, ".chock", "state", "s.json")}
    assert links.follow(root, ".chock/state/s.json") == expected
    assert links.follow(root, ".chock\\state\\s.json") == expected
    assert links.follow(root, flavour.join(root, ".chock", "state", "s.json")) == expected
    assert links.follow(root, "./.chock//state/./s.json") == expected


@pytest.mark.parametrize(("flavour", "root"), FLAVOURS)
def test_a_relative_link_and_a_dotdot_after_it_are_followed(
    flavour: ModuleType, root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    sep = flavour.sep
    Disk(
        flavour,
        {
            f"{root}/cfg": ".claude",
            f"{root}/src/up": f"..{sep}.cursor",
            f"{root}/chain1": "chain2",
            f"{root}/chain2": "AGENTS.md",
        },
        {},
        monkeypatch,
    )
    assert links.follow(root, "cfg/settings.json") == {_native(flavour, root, ".claude", "settings.json")}
    assert links.follow(root, "src/up/rules/a.mdc") == {_native(flavour, root, ".cursor", "rules", "a.mdc")}
    assert links.follow(root, "chain1") == {_native(flavour, root, "AGENTS.md")}


@pytest.mark.parametrize(("flavour", "root"), FLAVOURS)
def test_a_glob_names_the_links_it_matches(flavour: ModuleType, root: str, monkeypatch: pytest.MonkeyPatch) -> None:
    Disk(flavour, {f"{root}/notes.md": "AGENTS.md"}, {root: ["notes.md", "src", "notes.txt"]}, monkeypatch)
    assert links.follow(root, "not*.md") == {_native(flavour, root, "AGENTS.md")}
    assert links.follow(root, "no*") == {_native(flavour, root, "AGENTS.md"), _native(flavour, root, "notes.txt")}


def test_a_link_windows_reports_as_a_device_path_is_followed_to_the_file(monkeypatch: pytest.MonkeyPatch) -> None:
    Disk(
        ntpath,
        {
            "C:/r/notes.md": "\\\\?\\C:\\r\\AGENTS.md",
            "C:/r/cfg": "\\\\?\\C:\\r\\.claude",
            "C:/r/share": "\\\\?\\UNC\\srv\\share\\repo\\.claude",
            "C:/r/dot": "\\\\.\\C:\\r\\.chock\\config.yaml",
            "C:/r/other": "\\\\?\\D:\\elsewhere\\x",
        },
        {},
        monkeypatch,
    )
    assert links.follow("C:\\r", "notes.md") == {"C:\\r\\AGENTS.md"}
    assert links.follow("C:\\r", "cfg\\settings.json") == {"C:\\r\\.claude\\settings.json"}
    assert links.follow("C:\\r", "share/x") == {"\\\\srv\\share\\repo\\.claude\\x"}
    assert links.follow("C:\\r", "dot") == {"C:\\r\\.chock\\config.yaml"}
    assert links.follow("C:\\r", "other") == {"D:\\elsewhere\\x"}
    assert links.follow("C:\\r", "\\\\?\\C:\\r\\notes.md") == {"C:\\r\\AGENTS.md"}
    assert links.follow("C:\\r", "C:/r\\src/../notes.md") == {"C:\\r\\AGENTS.md"}


def test_a_rooted_path_with_no_drive_is_on_the_current_drive(monkeypatch: pytest.MonkeyPatch) -> None:
    Disk(ntpath, {}, {}, monkeypatch)
    assert links.follow("C:\\r", "\\r\\a") == {"\\r\\a"}
    assert links.follow("C:\\r", "\\\\srv\\share\\repo\\a") == {"\\\\srv\\share\\repo\\a"}


@pytest.mark.parametrize(
    ("real", "there", "inside"),
    [
        ("C:\\r", "C:\\r\\.claude\\x", ".claude/x"),
        ("C:\\r", "c:\\R\\AGENTS.md", "AGENTS.md"),
        ("C:/r", "C:\\r", "."),
        ("C:\\r\\", "C:\\r\\a", "a"),
        ("C:\\r", "C:\\rr\\a", "C:/rr/a"),
        ("C:\\r", "D:\\x", "D:/x"),
        ("\\\\srv\\share\\repo", "\\\\SRV\\share\\repo\\.chock\\x", ".chock/x"),
        ("/work/repo", "/work/repo/a", "a"),
        ("/work/repo", "/work/repo", "."),
        ("/work/repo", "/work/repoX/a", "/work/repoX/a"),
        ("/work/repo", "/Work/Repo/a", "/Work/Repo/a"),
        ("/work/repo", "/work/repo\\a\\b", "a/b"),
    ],
)
def test_a_followed_path_is_read_from_the_repository_folder(real: str, there: str, inside: str) -> None:
    assert links.within(real, there) == inside


class _Stub(reach.Reach):
    """A walk with only what `_linked` reads."""

    def __init__(self, base: str, cwd: str | None) -> None:
        self.hit, self.normal, self.base, self.cwd = pathset.hit, pathset.normalise, base, cwd
        self.root = self.normal(base)
        self.entries = [self.normal(e).strip("/") for e in pathset.PROTECTED]


@pytest.mark.parametrize(("flavour", "root"), FLAVOURS)
def test_the_shell_guard_judges_a_link_by_what_it_names_under_either_path_rules(
    flavour: ModuleType, root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    Disk(
        flavour,
        {
            f"{root}/notes.md": "AGENTS.md",
            f"{root}/innocent": "src/real.txt",
            f"{root}/cfg": ".claude",
            f"{root}/src/up": "../.cursor",
        },
        {},
        monkeypatch,
    )
    monkeypatch.setattr(
        reach, "os", SimpleNamespace(path=SimpleNamespace(realpath=lambda p: p, expanduser=os.path.expanduser))
    )
    walk = _Stub(root, ".")
    assert walk._linked("notes.md", {}, parents=False)
    assert walk._linked("cfg/commands/a.md", {}, parents=False)
    assert walk._linked("cfg", {}, parents=True)
    assert not walk._linked("innocent", {}, parents=False)
    assert not walk._linked("src/real.txt", {}, parents=False)
    assert _Stub(root, "src")._linked("up/rules/a.mdc", {}, parents=False)


@pytest.mark.parametrize(("flavour", "root"), FLAVOURS)
def test_the_tool_gate_lets_an_engine_state_write_through_and_refuses_a_link_out_of_it(
    flavour: ModuleType, root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    Disk(
        flavour,
        {
            f"{root}/notes.md": "AGENTS.md",
            f"{root}/.chock/state/l": f"{root}/.chock/config.yaml".replace("/", flavour.sep),
        },
        {},
        monkeypatch,
    )
    monkeypatch.setattr(
        gate_script, "os", SimpleNamespace(path=SimpleNamespace(realpath=lambda _p: root, relpath=os.path.relpath))
    )
    repo = Path(root)
    state = flavour.join(root, ".chock", "state", "s.json")
    assert gate_script.judge(repo, state) == ""
    assert gate_script.judge(repo, ".chock/state/s.json") == ""
    assert gate_script.judge(repo, ".chock\\state\\s.json") == ""
    assert gate_script.judge(repo, flavour.join(root, "notes.md")) == gate_script.BLOCK
    assert gate_script.judge(repo, flavour.join(root, ".chock", "state", "l")) == gate_script.BLOCK
    assert gate_script.judge(repo, flavour.join(root, "src", "a.py")) == ""


def test_the_tool_gate_follows_a_device_path_link_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    Disk(ntpath, {"C:/r/notes.md": "\\\\?\\C:\\r\\AGENTS.md"}, {}, monkeypatch)
    monkeypatch.setattr(
        gate_script, "os", SimpleNamespace(path=SimpleNamespace(realpath=lambda _p: "C:\\r", relpath=os.path.relpath))
    )
    assert gate_script.judge(Path("C:/r"), "C:\\r\\notes.md") == gate_script.BLOCK
    assert gate_script.judge(Path("C:/r"), "\\\\?\\C:\\r\\notes.md") == gate_script.BLOCK
