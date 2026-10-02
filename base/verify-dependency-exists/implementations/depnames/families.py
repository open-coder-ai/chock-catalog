"""Which path is which manifest: a Family says its ecosystem (for normalisation), whether it is a lock, and its reader."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import NamedTuple

from depnames import dart, dotnet, elixir, golang, gradle, lockfiles, maven, node, php, pyreq, pytoml, ruby, rust, swift


class Family(NamedTuple):
    eco: str
    kind: str
    read: Callable[[str], list[str]]
    lock: bool = False


REQUIREMENTS = Family("py", "requirements", pyreq.requirement_names)
_REQ_NAME = re.compile(r"^(?:.*[-_.])?(?:requirements|constraints)(?:[-_.].*)?\.(?:txt|in)$")
_REQ_DIR_FILE = re.compile(r"\.(?:txt|in)$")
_EXACT = {
    "pyproject.toml": Family("py", "pyproject.toml", pytoml.pyproject_names),
    "pipfile": Family("py", "Pipfile", pytoml.pipfile_names),
    "setup.cfg": Family("py", "setup.cfg", pyreq.setup_cfg_names),
    "setup.py": Family("py", "setup.py", pyreq.setup_py_names),
    "package.json": Family("npm", "package.json", node.package_json_names),
    "cargo.toml": Family("cargo", "Cargo.toml", rust.cargo_names),
    "gemfile": Family("gem", "Gemfile", ruby.gemfile_names),
    "gems.rb": Family("gem", "gems.rb", ruby.gemfile_names),
    "composer.json": Family("composer", "composer.json", php.composer_names),
    "pom.xml": Family("maven", "pom.xml", maven.pom_names),
    "libs.versions.toml": Family("maven", "version catalog", gradle.version_catalog_names),
    "packages.config": Family("nuget", "packages.config", dotnet.dotnet_names),
    "go.mod": Family("go", "go.mod", golang.go_mod_names),
    "mix.exs": Family("hex", "mix.exs", elixir.mix_names),
    "pubspec.yaml": Family("pub", "pubspec.yaml", dart.pubspec_names),
    "package.swift": Family("swift", "Package.swift", swift.package_swift_names),
    "package-lock.json": Family("npm", "package-lock.json", lockfiles.package_lock_names, lock=True),
    "npm-shrinkwrap.json": Family("npm", "npm-shrinkwrap.json", lockfiles.package_lock_names, lock=True),
    "yarn.lock": Family("npm", "yarn.lock", lockfiles.yarn_lock_names, lock=True),
    "pnpm-lock.yaml": Family("npm", "pnpm-lock.yaml", lockfiles.pnpm_lock_names, lock=True),
    "poetry.lock": Family("py", "poetry.lock", lockfiles.toml_lock_names, lock=True),
    "uv.lock": Family("py", "uv.lock", lockfiles.toml_lock_names, lock=True),
    "cargo.lock": Family("cargo", "Cargo.lock", lockfiles.cargo_lock_names, lock=True),
    "go.sum": Family("go", "go.sum", lockfiles.go_sum_names, lock=True),
    "gemfile.lock": Family("gem", "Gemfile.lock", lockfiles.gemfile_lock_names, lock=True),
    "composer.lock": Family("composer", "composer.lock", lockfiles.composer_lock_names, lock=True),
}
_SUFFIX = {
    ".gemspec": Family("gem", "gemspec", ruby.gemfile_names),
    ".gradle": Family("maven", "Gradle script", gradle.gradle_names),
    ".gradle.kts": Family("maven", "Gradle script", gradle.gradle_names),
    ".csproj": Family("nuget", "project file", dotnet.dotnet_names),
    ".fsproj": Family("nuget", "project file", dotnet.dotnet_names),
    ".vbproj": Family("nuget", "project file", dotnet.dotnet_names),
    ".props": Family("nuget", "MSBuild props", dotnet.dotnet_names),
    ".targets": Family("nuget", "MSBuild targets", dotnet.dotnet_names),
}


def family(path: str) -> Family | None:
    """The reader for a repo-relative path, matched on its lowercased name (case-insensitive file systems exist)."""
    pure = PurePosixPath(path.replace("\\", "/"))
    name = pure.name.lower()
    if found := _EXACT.get(name):
        return found
    if name.startswith("package") and name.endswith(".swift"):
        return _EXACT["package.swift"]
    if name.endswith(".versions.toml"):
        return _EXACT["libs.versions.toml"]
    if _REQ_NAME.match(name) or (pure.parent.name.lower() == "requirements" and _REQ_DIR_FILE.search(name)):
        return REQUIREMENTS
    return next((fam for suffix, fam in _SUFFIX.items() if name.endswith(suffix)), None)
