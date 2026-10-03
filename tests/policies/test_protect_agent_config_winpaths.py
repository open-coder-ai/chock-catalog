"""protect-agent-config 0.3.2: the Edit/Write gate reads Windows absolute paths (drive, device, UNC) from the repository folder."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policies import guardkit, scriptkit

POLICY = "protect-agent-config"
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")
pathset = guardkit.load_guard(POLICY, "pathset")
plugin = guardkit.load_guard(POLICY, "pathplugin")


@pytest.mark.parametrize(
    ("root", "path", "rel"),
    [
        ("C:/r", "C:\\r\\plug\\hooks\\h.json", "plug/hooks/h.json"),
        ("C:\\r", "C:/r/plug/hooks/h.json", "plug/hooks/h.json"),
        ("C:/r", "c:/R/PLUG/Hooks/h.json", "PLUG/Hooks/h.json"),
        ("C:/r", "C:\\r\\plug\\..\\src\\a.ts", "src/a.ts"),
        ("C:/r", "\\\\?\\C:\\r\\plug\\hooks\\h.json", "plug/hooks/h.json"),
        ("C:/r", "\\\\.\\C:\\r\\a", "a"),
        ("C:/r", "C:\\r", "."),
        ("C:/r/", "C:\\r\\a", "a"),
        ("C:/", "C:\\a\\b", "a/b"),
        ("C:/r", "\\r\\a", "a"),
        ("C:/r", "/r/a", "a"),
        ("C:/r", "\\other\\a", "/other/a"),
        ("C:/r", "C:\\rr\\a", "C:/rr/a"),
        ("C:/r", "C:\\elsewhere\\a", "C:/elsewhere/a"),
        ("C:/r", "D:\\r\\a", "D:/r/a"),
        ("C:/r", "src\\a.ts", "src/a.ts"),
        ("//srv/share/repo", "\\\\srv\\share\\repo\\AGENTS.md", "AGENTS.md"),
        ("\\\\srv\\share\\repo", "\\\\?\\UNC\\srv\\share\\repo\\.claude\\x", ".claude/x"),
        ("//srv/share/repo", "\\\\srv\\share\\other\\AGENTS.md", "//srv/share/other/AGENTS.md"),
        ("//srv/share/repo", "C:\\a", "C:/a"),
        ("/work/repo", "/work/repo/a/b", "a/b"),
        ("/work/repo", "/elsewhere/a", "/elsewhere/a"),
        ("/work/repo", "C:\\a", "C:/a"),
        ("/work/repo", "a\\b", "a/b"),
    ],
)
def test_a_windows_absolute_path_is_read_from_the_repository_folder(root: str, path: str, rel: str) -> None:
    assert gate_script.relative(Path(root), path) == rel


class FakeDisk:
    """A folder tree the plugin lookup reads instead of the real disk: keys are lowercase paths with slashes."""

    def __init__(self, tree: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch) -> None:
        self.tree = tree
        monkeypatch.setattr(plugin.os, "listdir", self.listdir)
        monkeypatch.setattr(plugin.os.path, "isdir", lambda p: self.key(p).endswith("/.claude-plugin"))

    @staticmethod
    def key(path: str) -> str:
        slashed = path.replace("\\", "/").lower()
        return slashed if slashed.endswith(":/") else slashed.rstrip("/")

    def listdir(self, path: str) -> list[str]:
        try:
            return self.tree[self.key(path)]
        except KeyError:
            raise FileNotFoundError(path) from None


def test_a_plugin_root_on_another_drive_is_found_from_the_drive(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeDisk(
        {
            "c:/": ["elsewhere"],
            "c:/elsewhere": ["plug", "app"],
            "c:/elsewhere/plug": [".claude-plugin", "hooks"],
            "c:/elsewhere/app": ["hooks"],
        },
        monkeypatch,
    )
    assert plugin.plugin_hooks("c:/elsewhere/plug/hooks/h.json")
    assert not plugin.plugin_hooks("c:/elsewhere/app/hooks/h.ts")
    assert not plugin.plugin_hooks("c:/missing/plug/hooks/h.json")
    assert pathset.verdict("C:\\Elsewhere\\Plug\\Hooks\\h.json") == pathset.BLOCK
    assert pathset.verdict("D:/elsewhere/plug/hooks/h.json") == ""


def test_the_gate_refuses_a_windows_path_into_a_plugin_roots_hooks_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path("C:/r")
    real = os.path.realpath(root)
    FakeDisk(
        {
            FakeDisk.key(real): ["plug", "src"],
            FakeDisk.key(f"{real}/plug"): [".claude-plugin", "hooks"],
            FakeDisk.key(f"{real}/src"): ["hooks"],
        },
        monkeypatch,
    )
    judge = gate_script.judge
    for path in (
        "C:\\r\\plug\\hooks\\h.json",
        "C:/r/plug/hooks/h.json",
        "c:/R/Plug/HOOKS/h.json",
        "\\\\?\\C:\\r\\plug\\hooks\\h.json",
        "C:\\r\\plug\\.claude-plugin\\plugin.json",
        "C:\\r\\.claude\\settings.json",
    ):
        assert judge(root, path) == "block", path
    for path in ("C:\\r\\src\\hooks\\useThing.ts", "C:\\r\\src\\app.py", "C:\\elsewhere\\plug\\hooks\\h.json"):
        assert judge(root, path) == "", path


def test_the_repository_folder_below_a_docs_folder_does_not_turn_its_instruction_files_into_questions() -> None:
    root = Path("C:/work/docs/proj")
    for path in ("C:/work/docs/proj/AGENTS.md", "C:\\work\\docs\\proj\\AGENTS.md", "c:/WORK/docs/proj/src/CLAUDE.md"):
        assert gate_script.judge(root, path) == "block", path
    assert gate_script.judge(root, "C:/work/docs/proj/docs/AGENTS.md") == "ask"
    assert gate_script.judge(root, "C:/work/docs/other/AGENTS.md") == "ask"
    unc = Path("//srv/docs/repo")
    assert gate_script.judge(unc, "\\\\srv\\docs\\repo\\AGENTS.md") == "block"
    assert gate_script.judge(unc, "\\\\srv\\docs\\repo\\docs\\AGENTS.md") == "ask"


def test_a_posix_repository_folder_under_docs_is_read_the_same_way(tmp_path: Path) -> None:
    root = scriptkit.init_repo(tmp_path / "docs" / "proj")
    assert gate_script.judge(root, f"{root}/AGENTS.md") == "block"
    assert gate_script.judge(root, f"{root}/docs/AGENTS.md") == "ask"
