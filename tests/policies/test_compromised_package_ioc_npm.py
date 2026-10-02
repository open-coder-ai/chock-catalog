"""compromised-package-ioc: what each npm-family reader lists, aliases and odd shapes included."""

from __future__ import annotations

import json

import pytest
from policies.iockit import iocscan, npm


def pairs(hits: object) -> list[tuple[str, str | None]]:
    return [(h.name, h.version) for h in hits]


@pytest.mark.parametrize(
    ("spec", "want"),
    [
        ("1.2.3", "1.2.3"),
        (" = v1.2.3 ", "1.2.3"),
        ("V1.2.3-rc.1+b", "1.2.3-rc.1+b"),
        ("^1.2.3", None),
        ("1.2", None),
        (3, None),
    ],
)
def test_exact(spec: object, want: str | None) -> None:
    assert npm.exact(spec) == want


def test_split_at_keeps_a_scope() -> None:
    assert npm.split_at("@a/b@1") == ("@a/b", "1")
    assert npm.split_at("@a/b") == ("@a/b", "")


def test_package_json_lists_every_section_alias_bundle_override_and_resolution() -> None:
    doc = {
        "dependencies": {"axios": "1.14.1", "web": "npm:@nx/js@21.5.0"},
        "devDependencies": "not an object",
        "peerDependencies": {"chalk": "^5.0.0"},
        "bundleDependencies": ["postmark-mcp", 7],
        "bundledDependencies": "no",
        "overrides": {"foo@1": {".": "1.0.0", "debug": "4.4.2"}, "keyv": "6.0.0", ".": "x"},
        "resolutions": {"**/@scope/pkg@1": "2.0.0", "a/b/color": "5.0.1", "x": 1},
    }
    got = pairs(npm.package_json(json.dumps(doc)))
    assert ("axios", "1.14.1") in got
    assert ("web", None) in got
    assert ("@nx/js", "21.5.0") in got
    assert ("chalk", None) in got
    assert ("postmark-mcp", None) in got
    assert ("foo", "1.0.0") in got
    assert ("debug", "4.4.2") in got
    assert ("keyv", "6.0.0") in got
    assert ("@scope/pkg", "2.0.0") in got
    assert ("color", "5.0.1") in got
    assert ("x", None) in got


def test_package_json_reads_pnpm_overrides() -> None:
    doc = {"pnpm": {"overrides": {"axios": "1.14.1", "foo@1>debug": "4.4.2"}}}
    assert pairs(npm.package_json(json.dumps(doc))) == [("axios", "1.14.1"), ("debug", "4.4.2")]
    assert pairs(npm.package_json(json.dumps({"pnpm": "x"}))) == []


def test_a_package_json_without_dependencies_names_nothing() -> None:
    assert pairs(npm.package_json('{"name": "a", "resolutions": []}')) == []


@pytest.mark.parametrize("text", ["{", "[]", '"x"'])
def test_a_package_json_that_is_not_a_json_object_is_unparseable(text: str) -> None:
    with pytest.raises(iocscan.UnparseableError):
        list(npm.package_json(text))


def test_package_lock_v3_reads_nested_scoped_workspace_and_aliased_entries() -> None:
    doc = {
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/a/node_modules/@nx/key": {"version": "5.0.7"},
            "node_modules/http": {"name": "axios", "version": "1.14.1"},
            "node_modules/same": {"name": "same", "version": "1.0.0"},
            "packages/web": {"name": "web", "version": "0.0.1"},
            "packages/anon": {"version": "0.0.1"},
            "node_modules/broken": "x",
        }
    }
    got = pairs(npm.package_lock(json.dumps(doc)))
    assert ("@nx/key", "5.0.7") in got
    assert ("http", "1.14.1") in got
    assert ("axios", "1.14.1") in got
    assert ("web", "0.0.1") in got
    assert ("root", "1.0.0") not in got
    assert got.count(("same", "1.0.0")) == 1


def test_package_lock_v1_walks_nested_dependencies_and_aliases() -> None:
    doc = {
        "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"debug": {"version": "4.4.2"}}},
            "b": {"version": "npm:chalk@5.6.1"},
            "c": "x",
        }
    }
    got = pairs(npm.package_lock(json.dumps(doc)))
    assert {("a", "1.0.0"), ("debug", "4.4.2"), ("b", None), ("chalk", "5.6.1")} <= set(got)


def test_yarn_lock_classic_and_berry_with_aliases() -> None:
    text = (
        "# yarn lockfile v1\n\n"
        '"@nx/js@^21.0.0", "@nx/js@^21.5.0":\n  version "21.5.0"\n\n'
        'http@npm:axios@1.14.1:\n  version "1.14.1"\n\n'
        '"keyv@npm:^6.0.0":\n  version: 6.0.0\n  resolution: "keyv@npm:6.0.0"\n'
    )
    got = pairs(npm.yarn_lock(text))
    assert got.count(("@nx/js", "21.5.0")) == 1
    assert ("axios", "1.14.1") in got
    assert ("http", "1.14.1") in got
    assert ("keyv", "6.0.0") in got


def test_pnpm_lock_reads_v5_v6_and_v9_keys_and_skips_non_keys() -> None:
    text = (
        "packages:\n"
        "  /axios/1.14.1:\n"
        "  /@nx/devkit@21.5.0(nx@21.5.0):\n"
        "  '@ctrl/tinycolor@4.1.2':\n"
        "  keyv@6.0.0_peer@1:\n"
        "  debug@4.4.2: {resolution: {integrity: x}}\n"
        "  chalk@5.6.1: # c\n"
        "  ? color@5.0.1\n"
        "  ? color@5.0.2\n  : !!map {}\n"
        "  nx@21.5.0: &a !!map\n"
        "    resolution: {integrity: x}\n"
        "    debug@4.4.2 not a key\n"
        "importers:\n  .:\n    dependencies:\n      chalk:\n        version: 5.6.1\n"
    )
    got = pairs(npm.pnpm_lock(text))
    assert got == [
        ("axios", "1.14.1"),
        ("@nx/devkit", "21.5.0"),
        ("@ctrl/tinycolor", "4.1.2"),
        ("keyv", "6.0.0"),
        ("debug", "4.4.2"),
        ("chalk", "5.6.1"),
        ("color", "5.0.1"),
        ("color", "5.0.2"),
        ("nx", "21.5.0"),
    ]


def test_bun_lock_reads_the_leading_descriptor_and_tolerates_trailing_commas() -> None:
    text = (
        '{\n  // bun\n  "packages": {\n    "nx": ["nx@21.5.0", "", {}],\n    "ws": ["web@workspace:packages/web"],\n'
        '    "e": [],\n    "n": [3],\n    "s": "x",\n  },\n}\n'
    )
    assert pairs(npm.bun_lock(text)) == [("nx", "21.5.0"), ("web", None)]
    assert pairs(npm.bun_lock('{"lockfileVersion": 1}')) == []
    assert pairs(npm.bun_lock("[]")) == []


def test_an_invalid_bun_lock_is_unparseable() -> None:
    with pytest.raises(iocscan.UnparseableError, match="JSONC"):
        list(npm.bun_lock('{"packages": {'))
