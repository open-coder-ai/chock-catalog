"""package-lifecycle-scripts: review round 3, false positives and continuations, each pinned."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from policies import lifecyclekit

mod = lifecyclekit.load_gate()
executed = mod.npm_script.__globals__["runs"].__wrapped__.__globals__["executed"]


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
    assert [path for path, _primary in executed(body)] == files


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


# Round 4: the ways a hook runs scripts/a.js, each a target when only that file is edited.


@pytest.mark.parametrize(
    "body",
    [
        "node scripts/a",
        "node scripts",
        "node -r ts-node/register scripts/a.js",
        "node --require=./scripts/a.js x",
        "sh -c 'node scripts/a.js'",
        'bash -c "scripts/a.js"',
        "node --max-old-space-size 4096 scripts/a.js",
        "python -W ignore scripts/a.js",
        "npx --yes tsx scripts/a.js",
        "env -i node scripts/a.js",
        "sudo -E node scripts/a.js",
        "time -p node scripts/a.js",
        "pnpm exec node scripts/a.js",
        "yarn node scripts/a.js",
        "npm exec -- node scripts/a.js",
        "bun x tsx scripts/a.js",
        "yarn tsx scripts/a.js",
        "FOO='a b' node scripts/a.js",
        "(node scripts/a.js)",
        "if true; then node scripts/a.js; fi",
        "node scripts/a.js>log",
        "node scripts/a.js > /dev/null 2>&1 || true",
        "node build.js scripts/a.js",
        "C:\\tools\\node.exe scripts\\a.js",
        "sh -c 'unbalanced",
        "npx zx scripts/a.mjs",
        "zx scripts/a",
        "babel-node scripts/a.js",
        "esno scripts/a.ts",
        "vite-node scripts/a",
        "source scripts/a.sh",
        ". scripts/a.sh",
        "cmd /c scripts\\a.cmd",
        "node -e \"try{require('./scripts/a')}catch(e){}\"",
    ],
)
def test_hook_shapes_that_run_a_script(tmp_path: Path, body: str) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"postinstall": body}}), "utf-8")
    named = re.search(r"scripts[/\\]a(\.\w+)?", body)
    target = (
        "scripts/index.js" if body == "node scripts" else "scripts/a" + (named.group(1) or ".js" if named else ".js")
    )
    expected = [] if "unbalanced" in body else [("npm-lifecycle-target", "ask")]
    assert found({target: "x"}, str(tmp_path)) == expected


def test_a_redirect_target_is_not_a_script(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "node a.js > out.js; node b.js >out.js"}}), "utf-8"
    )
    assert found({"out.js": "x"}, str(tmp_path)) == []


def test_only_the_run_file_written_in_the_same_change_escalates() -> None:
    package = json.dumps({"scripts": {"postinstall": "node build.js data.json"}})
    data = found({"package.json": package, "data.json": "{}"})
    assert data == [("npm-lifecycle-target", "ask"), ("npm-lifecycle", "ask")]
    build = found({"package.json": package, "build.js": "x"})
    assert build == [("npm-lifecycle-target", "ask"), ("npm-lifecycle", "block")]


def test_many_operands_and_many_written_files() -> None:
    body = "node " + " ".join(f"f{i}.js" for i in range(3000))
    writes = {"package.json": json.dumps({"scripts": {"postinstall": body}}), **{f"w{i}.txt": "x" for i in range(200)}}
    writes["f0.js"] = "x"
    assert ("npm-lifecycle", "block") in found(writes)
