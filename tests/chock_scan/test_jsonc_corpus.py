"""chock_scan.jsonc on real config files: vendored JSONC (corpus/jsonc/NOTICE.md) and this repo's own agent configs."""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

import pytest
from trees import ROOT

CORPUS = Path(__file__).parent / "corpus" / "jsonc"
VENDORED = sorted(CORPUS.glob("*.json"))
#: This repository's agent configs, read in place: strict JSON, so the JSONC reading must equal json's.
OWN = [".claude/settings.json", ".gemini/settings.json", ".cursor/hooks.json", ".codex/hooks.json"]

#: A key path and the value it must hold; the commented-out keys around them must not appear.
EXPECTED = {
    "vscode.settings.json": (("chat.tools.terminal.autoApprove", "scripts/test.sh"), True),
    "copilot-chat.vscode-mcp.json": (("servers", "vscode-playwright-mcp", "command"), "npm"),
    "mastra.cursor-mcp.json": (("mcpServers", "mastra", "command"), "pnpx"),
    "templates-python.devcontainer.json": (("name",), "Python 3"),
    "vscode.devcontainer.json": (("postCreateCommand",), "./.devcontainer/post-create.sh"),
    "copilot-chat.devcontainer.json": (("onCreateCommand", "npmInstall"), "npm install || true"),
    "vscode-1.80.0.eslintrc.json": (("root",), True),
    "vscode.tsconfig.base.json": (("compilerOptions", "strict"), True),
    "vscode.tasks.json": (("version",), "2.0.0"),
    "vscode.launch.json": (("version",), "0.1.0"),
    "vscode.extensions.json": (
        ("recommendations",),
        [
            "dbaeumer.vscode-eslint",
            "github.vscode-pull-request-github",
            "ms-vscode.vscode-github-issue-notebooks",
            "ms-vscode.extension-test-runner",
            "typescriptteam.native-preview",
            "ms-vscode.ts-customized-language-service",
            "connor4312.esbuild-problem-matchers",
        ],
    ),
}


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _at(value: object, path: tuple[str, ...]) -> object:
    for key in path:
        assert isinstance(value, dict), path
        value = value[key]
    return value


def test_every_vendored_file_is_listed_with_an_expectation_and_a_notice() -> None:
    assert {p.name for p in VENDORED} == set(EXPECTED)
    notice = _read(CORPUS / "NOTICE.md")
    assert all(f"`{name}`" in notice for name in EXPECTED)


@pytest.mark.parametrize("path", VENDORED, ids=[p.name for p in VENDORED])
def test_a_vendored_config_loads_with_its_keys_and_no_duplicates(jsonc: ModuleType, path: Path) -> None:
    text = _read(path)
    doc = jsonc.loads(text)
    assert doc.duplicates == ()
    keys, want = EXPECTED[path.name]
    assert _at(doc.value, keys) == want
    assert len(jsonc.strip(text)) == len(text)


def test_commented_out_keys_stay_hidden(jsonc: ModuleType) -> None:
    doc = jsonc.loads(_read(CORPUS / "templates-python.devcontainer.json"))
    assert set(doc.value) == {"name", "image"}
    settings = jsonc.loads(_read(CORPUS / "vscode.settings.json")).value
    assert "editor.experimental.preferTreeSitter.typescript" not in settings


def test_a_duplicate_added_to_a_real_file_is_reported(jsonc: ModuleType) -> None:
    text = _read(CORPUS / "copilot-chat.vscode-mcp.json")
    hostile = text.replace('"inputs": []', '"inputs": [],\n\t"servers": {} // hides the server above')
    doc = jsonc.loads(hostile)
    assert doc.value["servers"] == {}
    assert [d.path for d in doc.duplicates] == [("servers",)]
    assert doc.duplicates[0].values[0]["vscode-playwright-mcp"]["command"] == "npm"


@pytest.mark.parametrize("rel", OWN)
def test_this_repos_agent_configs_read_exactly_as_json_reads_them(jsonc: ModuleType, rel: str) -> None:
    text = _read(ROOT / rel)
    assert jsonc.loads(text) == (json.loads(text), ())
