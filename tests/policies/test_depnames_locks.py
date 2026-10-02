"""verify-dependency-exists: lockfile readers and the path-to-reader table."""

from __future__ import annotations

import pytest
from policies import depkit

_, r = depkit.load()
lockfiles = r.lockfiles
families = r.families


def names(reader, text: str) -> list[str]:
    return sorted(reader(text))


def test_lockfiles() -> None:
    package_lock = (
        '{"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/a": {}, "node_modules/a/node_modules/@s/b": {},'
        ' "packages/local": {}}, "dependencies": {"c": {"dependencies": {"d": {}}}, "e": 1}}'
    )
    assert names(lockfiles.package_lock_names, package_lock) == ["@s/b", "a", "c", "d", "e"]
    assert lockfiles.package_lock_names("[]") == []
    assert lockfiles.package_lock_names('{"packages": 1, "dependencies": []}') == []
    yarn = '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.0"\nleft-pad@^1.0.0:\n  version "1.3.0"\nberry@npm:^1:\n  resolution: x\n'
    assert names(lockfiles.yarn_lock_names, yarn) == ["@babel/core", "berry", "left-pad"]
    pnpm = (
        "lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\npackages:\n  accepts@1.3.8:\n    resolution: {}\n"
        "  '@babel/core@7.0.0':\n    resolution: {}\n  /legacy@2.0.0:\n  /old/1.2.3:\n  /@s/old/1.2.3:\nsnapshots:\n  accepts@1.3.8: {}\n"
    )
    assert names(lockfiles.pnpm_lock_names, pnpm) == ["@babel/core", "@s/old", "accepts", "accepts", "legacy", "old"]
    toml = '[[package]]\nname = "a"\nversion = "1"\n[[package]]\nversion = "2"\n[[package]]\nname = "b"\n'
    assert names(lockfiles.toml_lock_names, toml) == ["a", "b"]
    assert lockfiles.toml_lock_names('package = "x"\n') == []
    sums = "example.com/a v1.0.0 h1:abc=\nexample.com/a v1.0.0/go.mod h1:def=\n\nexample.com/b v2.0.0 h1:x=\n"
    assert names(lockfiles.go_sum_names, sums) == ["example.com/a", "example.com/a", "example.com/b"]
    gems = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0)\n      actionpack (= 7.0)\n    rake (13.0)\n\nDEPENDENCIES\n  rails\n"
    assert names(lockfiles.gemfile_lock_names, gems) == ["rails", "rake"]
    composer = '{"packages": [{"name": "a/b"}, {"x": 1}, 3], "packages-dev": [{"name": "c/d"}]}'
    assert names(lockfiles.composer_lock_names, composer) == ["a/b", "c/d"]
    assert lockfiles.composer_lock_names("[]") == []
    assert lockfiles.composer_lock_names('{"packages": null}') == []


@pytest.mark.parametrize(
    ("path", "kind", "lock"),
    [
        ("requirements.txt", "requirements", False),
        ("requirements-dev.txt", "requirements", False),
        ("dev-requirements.txt", "requirements", False),
        ("requirements/prod.txt", "requirements", False),
        ("a/Requirements/base.in", "requirements", False),
        ("constraints.txt", "requirements", False),
        ("constraints-3.9.txt", "requirements", False),
        ("a\\requirements.txt", "requirements", False),
        ("pkg/pyproject.toml", "pyproject.toml", False),
        ("Pipfile", "Pipfile", False),
        ("PACKAGE.JSON", "package.json", False),
        ("Cargo.toml", "Cargo.toml", False),
        ("x.gemspec", "gemspec", False),
        ("app/build.gradle.kts", "Gradle script", False),
        ("gradle/libs.versions.toml", "version catalog", False),
        ("Directory.Packages.props", "MSBuild props", False),
        ("a.fsproj", "project file", False),
        ("Package.swift", "Package.swift", False),
        ("Gemfile.lock", "Gemfile.lock", True),
        ("go.sum", "go.sum", True),
        ("sub/uv.lock", "uv.lock", True),
    ],
)
def test_family_by_path(path: str, kind: str, lock: bool) -> None:
    found = families.family(path)
    assert found is not None
    assert (found.kind, found.lock) == (kind, lock)


@pytest.mark.parametrize(
    "path", ["README.md", "requirements.md", "notes.txt", "src/main.py", "docs/requirements/readme.md", "txt"]
)
def test_other_paths_are_not_manifests(path: str) -> None:
    assert families.family(path) is None


def test_requirements_family_is_the_one_includes_resolve_to() -> None:
    assert families.family("requirements.txt") is families.REQUIREMENTS
