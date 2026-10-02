"""package-lifecycle-scripts: review round 3, false positives and continuations, each pinned."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import lifecyclekit

mod = lifecyclekit.load_gate()
executed = mod.npm_script.__globals__["executed"]


def found(writes: dict[str, str], root: str = "") -> list[tuple[str, str]]:
    return [(f["rule"], f["level"]) for f in mod.findings({"repo_root": root, "writes": writes})]


def keys(writes: dict[str, str]) -> list[str]:
    return [f["key"] for f in mod.findings({"writes": writes})]


@pytest.mark.parametrize(
    ("body", "files"),
    [
        ("node dist/index.js", ["dist/index.js"]),
        ("NODE_ENV=production node --no-warnings ./scripts/a.js --flag", ["./scripts/a.js"]),
        ("env X=1 sh 'tools/setup'", ["tools/setup"]),
        ("deno run main.ts", ["main.ts"]),
        ("npx tsx build.ts && ./bin/post", ["build.ts", "./bin/post"]),
        ("C:\\tools\\python.exe gen.py", ["gen.py"]),
        ("tsc -p tsconfig.json", []),
        ("cp a.txt b.txt; rimraf dist", []),
        ("node -e 1", []),
        ("FOO=1", []),
        ("", []),
    ],
)
def test_executed_files(body: str, files: list[str]) -> None:
    assert executed(body) == files


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    scripts = {
        "prepare": "tsc -p tsconfig.json",
        "postinstall": "node dist/index.js",
        "prepack": "node c.js package.json",
    }
    (tmp_path / "package.json").write_text(
        json.dumps({"homepage": "https://example.invalid", "scripts": scripts}), "utf-8"
    )
    return tmp_path


def test_data_arguments_and_the_manifest_itself_are_no_targets(repo: Path) -> None:
    root = str(repo)
    assert found({"tsconfig.json": '{"$schema": "https://json.schemastore.org/tsconfig"}'}, root) == []
    manifest = json.dumps({"homepage": "https://example.invalid", "version": "1.0.1"})
    assert found({"package.json": manifest}, root) == []


def test_an_executed_file_with_a_url_is_asked_about_not_blocked(repo: Path) -> None:
    text = "/*! MIT https://opensource.org/licenses/MIT */\nmodule.exports = 1\n"
    assert found({"dist/index.js": text}, str(repo)) == [("npm-lifecycle-target", "ask")]


@pytest.mark.parametrize(
    ("path", "one", "two"),
    [
        ("Podfile", "system 'echo',\n  'one'\n", "system 'echo',\n  'two'\n"),
        ("Podfile", "system 'echo', \\\n  'one'\n", "system 'echo', \\\n  'two'\n"),
        ("Podfile", "system 'a' +\n  'one'\n", "system 'a' +\n  'two'\n"),
        (
            "build.gradle",
            "tasks.register('x', Exec) {\n  commandLine 'echo',\n    'one'\n}\n",
            "tasks.register('x', Exec) {\n  commandLine 'echo',\n    'two'\n}\n",
        ),
    ],
)
def test_continued_statements_are_keyed_whole(path: str, one: str, two: str) -> None:
    assert keys({path: one}) != keys({path: two})


def test_a_complete_statement_does_not_swallow_the_next() -> None:
    assert keys({"Podfile": "system 'a'\npod 'one'\n"}) == keys({"Podfile": "system 'a'\npod 'two'\n"})


@pytest.mark.parametrize(
    "body",
    [
        "import os\nclass K:\n    def __init__(self):\n        os.system('echo')\nK()\n",
        "import os\nclass K:\n    def __new__(cls):\n        os.system('echo')\nk = K\n",
        "import os\ndef f():\n    pass\nglobals()['f']()\n",
    ],
)
def test_constructors_and_namespace_calls(body: str) -> None:
    assert found({"setup.py": body}) == [("setup-import-time", "ask")]


def test_a_class_never_named_runs_no_constructor() -> None:
    assert found({"setup.py": "import os\nclass K:\n    def __init__(self):\n        os.system('echo')\n"}) == []
