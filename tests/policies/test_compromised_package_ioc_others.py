"""compromised-package-ioc: the Go, Cargo, RubyGems and Composer readers, and path routing."""

from __future__ import annotations

import json

import pytest
from policies.iockit import iocscan, npm, others, python, route


def triples(hits: object) -> list[tuple[str, str, str | None]]:
    return [(h.ecosystem, h.name, h.version) for h in hits]


def test_semver() -> None:
    assert others._semver(" =v1.2.3 ") == "v1.2.3"
    assert others._semver("^0.3.10", "=^") == "0.3.10"
    assert others._semver("~0.3.10", "=^") is None
    assert others._semver("1.2", "=") is None
    assert others._semver(None) is None


def test_go_mod_reads_require_lines_blocks_and_replace_targets() -> None:
    text = (
        "module example.com/app // ours\n\ngo 1.22\ntoolchain go1.22.1\n\n"
        "require github.com/boltdb-go/bolt v1.3.1\n"
        "require (\n\tgolang.org/x/net v0.1.0 // indirect\n\n\texample.com/bare\n)\n"
        "replace (\n\tgithub.com/a/b v1.0.0 => github.com/BoltDB-Go/bolt v1.3.2\n\tgithub.com/c/d => ../local\n\tbroken line\n)\n"
        "replace github.com/e/f => github.com/g/h v2.0.0\n"
        "exclude github.com/boltdb-go/bolt v1.3.0\n"
        "require\n"
    )
    assert triples(others.go_mod(text)) == [
        ("go", "github.com/boltdb-go/bolt", "v1.3.1"),
        ("go", "golang.org/x/net", "v0.1.0"),
        ("go", "example.com/bare", None),
        ("go", "github.com/BoltDB-Go/bolt", "v1.3.2"),
        ("go", "../local", None),
        ("go", "github.com/g/h", "v2.0.0"),
    ]


def test_go_sum_reads_both_line_kinds() -> None:
    text = "github.com/boltdb-go/bolt v1.3.1 h1:x=\ngithub.com/boltdb-go/bolt v1.3.1/go.mod h1:y=\nshort\n"
    assert triples(others.go_sum(text)) == [("go", "github.com/boltdb-go/bolt", "v1.3.1")] * 2


def test_cargo_toml_reads_every_dependency_table_renames_and_patches() -> None:
    text = """
[package]
name = "app"
[dependencies]
arrayref = "0.3.10"
m = { package = "proc_macro1", version = "=1.0.107" }
odd = { package = 3 }
[dev-dependencies]
internment = "^0.8.7"
[build_dependencies]
tinymember = { git = "https://example.org/t" }
[target.'cfg(unix)'.dependencies]
aovine = "1"
[target.x]
dependencies = 1
[workspace.dependencies]
append-only-vec = "0.1.9"
[patch.crates-io]
arone = { path = "../arone" }
"""
    got = triples(others.cargo_toml(text))
    for want in [
        ("crates", "arrayref", "0.3.10"),
        ("crates", "proc_macro1", "1.0.107"),
        ("crates", "internment", "0.8.7"),
        ("crates", "tinymember", None),
        ("crates", "aovine", None),
        ("crates", "append-only-vec", "0.1.9"),
        ("crates", "arone", None),
    ]:
        assert want in got
    assert not [h for h in got if h[1] == "odd"]


def test_cargo_toml_with_odd_top_level_shapes_names_nothing() -> None:
    assert triples(others.cargo_toml('target = 1\npatch = 2\nworkspace = 3\n[package]\nname = "a"\n')) == []


def test_cargo_lock_reads_each_package() -> None:
    text = '[[package]]\nname = "arrayref"\nversion = "0.3.10"\n\n[[package]]\nversion = "1"\n\n'
    assert triples(others.toml_lock("crates", text)) == [("crates", "arrayref", "0.3.10")]
    assert triples(others.toml_lock("crates", "package = 1\n")) == []
    assert triples(others.toml_lock("crates", "package = [1]\n")) == []


def test_gemfile_and_gemspec_lines() -> None:
    text = (
        "source 'https://rubygems.org'\n"
        'gem "fastlane-plugin-telegram-proxy", "= 1.0.0", require: false\n'
        "gem('rails', '~> 7.1', '>= 7.1.2')\n"
        "gem 'puma', '6.4.2'\n"
        "gem 'a', '1.0', '2.0'\n"
        "spec.add_development_dependency 'fastlane-plugin-proxy_teleram'\n"
        '  s.add_runtime_dependency("x", "0.1.0")\n'
    )
    assert triples(others.gemfile(text)) == [
        ("rubygems", "fastlane-plugin-telegram-proxy", "1.0.0"),
        ("rubygems", "rails", None),
        ("rubygems", "puma", "6.4.2"),
        ("rubygems", "a", None),
        ("rubygems", "fastlane-plugin-proxy_teleram", None),
        ("rubygems", "x", "0.1.0"),
    ]


def test_gemfile_lock_reads_resolved_specs_only() -> None:
    text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n      racc (~> 1.4)\n    puma (6.4.2)\n"
    assert triples(others.gemfile_lock(text)) == [("rubygems", "nokogiri", "1.16.0"), ("rubygems", "puma", "6.4.2")]


def test_composer_files() -> None:
    manifest = {"require": {"php": ">=8.1", "intercom/intercom-php": "v5.0.2"}, "require-dev": "x"}
    assert triples(others.composer_json(json.dumps(manifest))) == [
        ("packagist", "php", None),
        ("packagist", "intercom/intercom-php", "5.0.2"),
    ]
    lock = {
        "packages": [{"name": "intercom/intercom-php", "version": "v5.0.2"}, {"version": "1"}, 3],
        "packages-dev": {},
    }
    assert triples(others.composer_lock(json.dumps(lock))) == [("packagist", "intercom/intercom-php", "v5.0.2")]


@pytest.mark.parametrize(
    ("reader", "text"),
    [
        (others.cargo_toml, "[dependencies\n"),
        (others.composer_json, "{"),
        (others.composer_lock, "[]"),
    ],
)
def test_an_unreadable_file_is_unparseable(reader: object, text: str) -> None:
    with pytest.raises(iocscan.UnparseableError):
        list(reader(text))


@pytest.mark.parametrize(
    ("path", "want"),
    [
        ("web/package.json", npm.package_json),
        ("PACKAGE-LOCK.JSON", npm.package_lock),
        ("Pipfile", python.pipfile),
        ("x/app.gemspec", others.gemfile),
        ("requirements.txt", python.requirements),
        ("requirements-dev.in", python.requirements),
        ("constraints.txt", python.requirements),
        ("requirements/test.txt", python.requirements),
        ("requirements/notes.md", None),
        ("docs/requirements.md", None),
        ("src/app.py", None),
    ],
)
def test_reader_routing(path: str, want: object) -> None:
    assert route.reader(path) is want


def test_cargo_lock_routes_to_the_crates_lock_reader() -> None:
    assert triples(route.reader("Cargo.lock")('[[package]]\nname = "aovine"\nversion = "1.0.0"\n')) == [
        ("crates", "aovine", "1.0.0")
    ]


@pytest.mark.parametrize(
    ("path", "want"),
    [
        (".github/workflows/ci.yml", True),
        ("sub/.GitHub/Workflows/ci.YAML", True),
        (".github/actions/setup/action.yml", True),
        ("action.yaml", True),
        (".github/workflows/nested/ci.yml", False),
        (".github/dependabot.yml", False),
    ],
)
def test_workflow_routing(path: str, want: bool) -> None:
    assert route.is_workflow(path) is want


def test_uses_lists_remote_actions_only() -> None:
    text = (
        "steps:\n  - uses: ./local\n  - uses: docker://alpine:3\n  - name: x\n    uses: 'tj-actions/changed-files/sub@v1' # c\n"
        '  - "uses": reviewdog/action-setup\njobs:\n  call:\n    uses: o/r/.github/workflows/w.yml@main\n'
    )
    assert list(route.uses(text)) == [
        ("tj-actions/changed-files", "v1", 5),
        ("reviewdog/action-setup", "", 6),
        ("o/r", "main", 9),
    ]
