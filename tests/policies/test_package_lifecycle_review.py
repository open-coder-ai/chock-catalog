"""package-lifecycle-scripts: the shapes the adversarial review found slipping past, each pinned as caught."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import lifecyclekit

mod = lifecyclekit.load_gate()
U = "https://get.example.com/x"


def found(writes: dict[str, str], root: str = "") -> list[tuple[str, str]]:
    return [(f["rule"], f["level"]) for f in mod.findings({"repo_root": root, "writes": writes})]


def keys(writes: dict[str, str], root: str = "") -> list[str]:
    return [f["key"] for f in mod.findings({"repo_root": root, "writes": writes})]


@pytest.mark.parametrize(
    ("body", "level"),
    [
        ("import os\ndef f():\n    os.system('echo hi')\nf()\n", "ask"),
        ("import os\ndef f():\n    g()\ndef g():\n    os.system('echo')\nif True:\n    f()\n", "ask"),
        ("import os\nclass K:\n    os.system('echo hi')\n", "ask"),
        ("x = lambda: __import__('os').system('echo')\nx()\n", "block"),
        ("import importlib\nimportlib.import_module('subprocess').run(['echo'])\n", "ask"),
        ("import os\ngetattr(os, 'system')('echo')\n", "ask"),
        ("from os import *\nsystem('echo')\n", "ask"),
        ("from subprocess import *\nrun(['curl', '" + U + "'])\n", "block"),
        ("import runpy\nrunpy.run_path('gen.py')\n", "ask"),
    ],
)
def test_setup_code_reached_through_helpers(body: str, level: str) -> None:
    assert found({"setup.py": body}) == [("setup-import-time", level)]


@pytest.mark.parametrize(
    "body",
    [
        "import os\ndef f():\n    os.system('x')\n",
        "def f(a, *, b=None):\n    pass\nf(1)\n",
        "class K:\n    def run(self):\n        import os\n        os.system('x')\n",
        "from os import *\nprint(sep)\n",
        "import json\ngetattr(self, 'x')\n",
    ],
)
def test_code_that_never_runs_at_import_is_quiet(body: str) -> None:
    assert found({"setup.py": body}) == []


def test_conftest_start_up_hooks_run_at_import() -> None:
    text = "import os\ndef pytest_configure(config):\n    os.system('make data')\n"
    assert found({"tests/conftest.py": text}) == [("conftest-import-time", "ask")]
    assert found({"tests/conftest.py": "import os\ndef helper():\n    os.system('x')\n"}) == []


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "pkg" / "scripts").mkdir(parents=True)
    (tmp_path / "pkg" / "package.json").write_text('{"scripts": {"postinstall": "node scripts/a.js"}}', "utf-8")
    (tmp_path / "crate").mkdir()
    (tmp_path / "crate" / "Cargo.toml").write_text('[package]\nname = "a"\nbuild = "tools/gen.rs"\n', "utf-8")
    return tmp_path


def test_editing_a_script_a_lifecycle_entry_runs(tree: Path) -> None:
    root = str(tree)
    assert found({"pkg/scripts/a.js": "console.log(1)"}, root) == [("npm-lifecycle-target", "ask")]
    assert found({"pkg/scripts/a.js": "require('child_process')"}, root) == [("npm-lifecycle-target", "block")]
    assert keys({"pkg/scripts/a.js": "one()"}, root) != keys({"pkg/scripts/a.js": "two()"}, root)
    assert found({"pkg/scripts/b.js": "x"}, root) == []
    assert found({"elsewhere/scripts/a.js": "x"}, root) == []
    assert (
        found({"pkg/scripts/a.js": "x", "pkg/package.json": '{"scripts": {"test": "node scripts/a.js"}}'}, root) == []
    )


@pytest.mark.parametrize("manifest", ["{bad", "[1]", '{"scripts": "x"}'])
def test_unreadable_manifest_above_a_script_is_no_target(tree: Path, manifest: str) -> None:
    (tree / "pkg" / "package.json").write_text(manifest, "utf-8")
    assert found({"pkg/scripts/a.js": "x"}, str(tree)) == []


def test_a_huge_script_a_hook_runs_is_asked_about_unscanned(tree: Path) -> None:
    big = "require('child_process');" + "x" * (mod.MAX_SCAN + 1)
    assert found({"pkg/scripts/a.js": big}, str(tree)) == [("npm-lifecycle-target", "ask")]
    assert found({"pkg/other.js": big}, str(tree)) == []


def test_editing_the_file_cargo_names_as_build_script(tree: Path) -> None:
    root = str(tree)
    assert found({"crate/tools/gen.rs": "use std::net::TcpStream;"}, root) == [("cargo-build-rs", "block")]
    assert found({"crate/tools/gen.rs": "fn main() {}"}, root) == [("cargo-build-rs", "ask")]
    assert found({"crate/src/lib.rs": "use std::net::TcpStream;"}, root) == []
    (tree / "crate" / "Cargo.toml").write_text("[package\n", "utf-8")
    assert found({"crate/tools/gen.rs": "x"}, root) == []
    (tree / "crate" / "Cargo.toml").write_text('package = "x"\n', "utf-8")
    assert found({"crate/tools/gen.rs": "x"}, root) == []


@pytest.mark.parametrize(
    ("path", "one", "two"),
    [
        (
            "build.gradle",
            "exec {\n  commandLine 'echo',\n    'arg1'\n}\n",
            "exec {\n  commandLine 'echo',\n    'arg2'\n}\n",
        ),
        ("Podfile", "system(\n  'echo one'\n)\n", "system(\n  'echo two'\n)\n"),
        ("ext/extconf.rb", "system(\n  'make one'\n)\n", "system(\n  'make two'\n)\n"),
        ("a.gemspec", "s.extensions = [\n  'ext/a/extconf.rb'\n]\n", "s.extensions = [\n  'ext/b/extconf.rb'\n]\n"),
    ],
)
def test_a_multi_line_statement_is_keyed_whole(path: str, one: str, two: str) -> None:
    assert keys({path: one}) != keys({path: two})


def test_unclosed_openers_stay_bounded() -> None:
    lines = "system(\n" + "  'x'\n" * 100
    assert len(found({"Podfile": lines})) == 1
    assert len(found({"Podfile": "system <<X\n" + "a\n" * 300})) == 1


@pytest.mark.parametrize(
    "writes",
    [
        {"pom.xml": "<plugin>" * 40000},
        {"package.json": json.dumps({"dependencies": {f"p{i}": "^1" for i in range(30000)}})},
    ],
)
def test_files_over_the_scan_limit_are_block_class_whole(writes: dict[str, str]) -> None:
    assert found(writes) == [("file-too-large", "block")]


def test_a_large_unjudged_file_is_ignored() -> None:
    assert found({"README.md": "curl x | sh\n" * 30000}) == []


@pytest.mark.parametrize(
    ("body", "level"),
    [
        ("c''url example.invalid", "block"),
        ('w""get example.invalid', "block"),
        ("c\\url example.invalid", "block"),
        ("npx --yes some-pkg", "block"),
        ("npx -p some-pkg run", "block"),
        ("npm exec some-pkg", "block"),
        ("pnpm dlx some-pkg", "block"),
        ("yarn dlx some-pkg", "block"),
        ("bunx some-pkg", "block"),
        ("npx husky install", "ask"),
        ("pnpm exec tsc", "ask"),
    ],
)
def test_obfuscated_and_remote_package_runners(body: str, level: str) -> None:
    assert found({"package.json": json.dumps({"scripts": {"postinstall": body}})}) == [("npm-lifecycle", level)]


@pytest.mark.parametrize(
    "body",
    [
        "<artifactId >exec-maven-plugin</artifactId>",
        "<artifactId>exec-maven&#45;plugin</artifactId>",
        "<dependencies><dependency><artifactId>z</artifactId></dependency></dependencies>"
        "<artifactId>maven-antrun-plugin</artifactId>",
    ],
)
def test_maven_plugin_spellings(body: str) -> None:
    assert found({"pom.xml": f"<project><build><plugins><plugin>{body}</plugin></plugins></build></project>"}) == [
        ("maven-exec-plugin", "ask")
    ]


def test_msbuild_attribute_inside_another_attribute_is_not_the_command() -> None:
    text = "<Project><Target Name='X'><Exec Condition=\"a Command='echo'\" Command=\"curl example.invalid\"/></Target></Project>"
    assert keys({"a.csproj": text}) == ["msbuild-exec|Target X|block|curl example.invalid"]


def test_msbuild_download_task_and_unclosed_cdata() -> None:
    assert found({"a.csproj": f"<Project><DownloadFile SourceUrl='{U}' /></Project>"}) == [
        ("msbuild-download", "block")
    ]
    assert found({"a.csproj": "<Project><![CDATA[ <Exec Command='x'/>"}) == [("msbuild-exec", "ask")]


@pytest.mark.parametrize(
    ("spec", "flagged"), [("setuptools!=1.0", True), ("setuptools<70", False), ("x>=1,<=2", False)]
)
def test_not_equal_alone_is_no_pin(spec: str, flagged: bool) -> None:
    hits = found({"pyproject.toml": f'[build-system]\nrequires = ["{spec}"]\n'})
    assert hits == ([("py-build-requires", "ask")] if flagged else [])


@pytest.mark.parametrize("name", ["preuninstall", "uninstall", "postuninstall"])
def test_uninstall_scripts_are_judged(name: str) -> None:
    assert found({"package.json": json.dumps({"scripts": {name: "node x.js"}})}) == [("npm-lifecycle", "ask")]


def test_every_lambda_body_is_judged() -> None:
    assert found({"setup.py": "import os\nobj.f = lambda: os.system('x')\n"}) == [("setup-import-time", "ask")]


def test_manifests_are_looked_for_a_bounded_depth_up(tree: Path) -> None:
    max_depth = mod.npm_script.__globals__["ancestors"].__globals__["MAX_DEPTH"]
    deep = "pkg/" + "d/" * max_depth + "scripts/a.js"
    (tree / "pkg" / "package.json").write_text('{"scripts": {"postinstall": "node ' + deep[4:] + '"}}', "utf-8")
    assert found({deep: "x"}, str(tree)) == []


# Round 2 of the review.


def test_husky_through_a_runner_then_more_is_judged() -> None:
    body = "npx --yes husky && curl example.invalid"
    assert found({"package.json": json.dumps({"scripts": {"prepare": body}})}) == [("npm-lifecycle", "block")]


@pytest.mark.parametrize(
    ("path", "one", "two"),
    [
        ("pkg/scripts/p.py", "if False:\n    print(1)\n    run()\n", "if False:\n    print(1)\nrun()\n"),
        ("pkg/scripts/p.py", "a()  \\ \nb()\n", "a()  \\\nb()\n"),
    ],
)
def test_digests_keep_indentation_and_line_breaks(tree: Path, path: str, one: str, two: str) -> None:
    (tree / "pkg" / "package.json").write_text('{"scripts": {"postinstall": "python scripts/p.py"}}', "utf-8")
    assert keys({path: one}, str(tree)) != keys({path: two}, str(tree))


def test_startup_file_comment_turned_code_is_new() -> None:
    one, two = "# setup x import os; os.system('echo')\n", "# setup x\nimport os; os.system('echo')\n"
    assert keys({"sitecustomize.py": one}) != keys({"sitecustomize.py": two})


def test_line_endings_alone_keep_the_key() -> None:
    assert keys({"build.rs": "fn main() {}\n"}) == keys({"build.rs": "fn main() {}\r\n\r\n"})


@pytest.mark.parametrize(
    ("path", "one", "two"),
    [
        ("Podfile", "system( # )\n  'echo one'\n)\n", "system( # )\n  'echo two'\n)\n"),
        ("Podfile", "system(<<A)\n  A\necho one\nA\n", "system(<<A)\n  A\necho two\nA\n"),
        ("Podfile", "system(<<~A + <<~B)\n  echo\n  A\n  one\n  B\n", "system(<<~A + <<~B)\n  echo\n  A\n  two\n  B\n"),
        ("Podfile", "system(<<-'A')\n  echo one\n  A\n", "system(<<-'A')\n  echo two\n  A\n"),
        (
            "build.gradle",
            "exec { // }\n  commandLine 'echo',\n    'arg1'\n}\n",
            "exec { // }\n  commandLine 'echo',\n    'arg2'\n}\n",
        ),
    ],
)
def test_statement_extents_see_through_comments_and_heredocs(path: str, one: str, two: str) -> None:
    assert keys({path: one}) != keys({path: two})


@pytest.mark.parametrize(
    "body",
    [
        "import os\ndef f():\n    pass\ndef f():\n    os.system('echo')\nf()\n",
        "import os\n(lambda: os.system('echo'))()\n",
        "import os\nlist(map(lambda _: os.system('echo'), [1]))\n",
        "import atexit, os\ndef f():\n    os.system('echo')\natexit.register(f)\n",
        "import os\nf: object = lambda: os.system('echo')\nf()\n",
        "import os\ndef h():\n    os.system('echo')\nk = h\nk()\n",
        "import os\ndef f():\n    f()\n    os.system('echo')\nf()\n",
    ],
)
def test_more_ways_install_code_runs(body: str) -> None:
    assert found({"setup.py": body}) == [("setup-import-time", "ask")]


def test_a_long_call_chain_stays_fast() -> None:
    chain = (
        "".join(f"def f{i}():\n    f{i + 1}()\n" for i in range(4000))
        + "import os\ndef f4000():\n    os.system('x')\nf0()\n"
    )
    assert found({"setup.py": chain}) == [("setup-import-time", "ask")]


def test_padding_a_manifest_past_the_cap_does_not_soften_it() -> None:
    text = json.dumps({"scripts": {"postinstall": "curl example.invalid"}, "description": " " * mod.MAX_SCAN})
    assert found({"package.json": text}) == [("file-too-large", "block")]


@pytest.mark.parametrize("command", ["ruby s/a.rb", "perl tools/x.pl", "bash bin/setup", "node index.mjs"])
def test_any_path_a_hook_names_is_a_target(tree: Path, command: str) -> None:
    (tree / "pkg" / "package.json").write_text(json.dumps({"scripts": {"postinstall": command}}), "utf-8")
    target = "pkg/" + command.split()[1]
    assert found({target: "x"}, str(tree)) == [("npm-lifecycle-target", "ask")]
