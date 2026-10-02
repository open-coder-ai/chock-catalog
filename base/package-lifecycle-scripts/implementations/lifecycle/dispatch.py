"""Which detector reads a path: by base name, case-insensitively (a case-insensitive disk reads Package.json too)."""

from __future__ import annotations

from pathlib import PurePosixPath

from lifecycle import Hit, gyp, npm, pyrules, targets, textrules, tomlrules, xmlrules

#: Detectors that also look at the rest of the change and the tree (sibling files, native sources).
WITH_TREE = {"package.json": npm.package_json, "binding.gyp": gyp.binding_gyp}
WITH_PATH = {
    "composer.json": npm.composer_json,
    "setup.py": pyrules.setup_py,
    "conftest.py": pyrules.conftest_py,
    "sitecustomize.py": pyrules.customize_py,
    "usercustomize.py": pyrules.customize_py,
    "pyproject.toml": tomlrules.pyproject,
    "cargo.toml": tomlrules.cargo_toml,
}
TEXT_ONLY = {
    "build.rs": textrules.build_rs,
    "extconf.rb": textrules.extconf,
    "podfile": textrules.podfile,
    "pom.xml": xmlrules.pom,
}
BY_SUFFIX = {
    ".pth": pyrules.pth,
    ".go": textrules.go_source,
    ".gradle": textrules.gradle,
    ".gradle.kts": textrules.gradle,
    ".gemspec": textrules.gemspec,
    ".podspec": textrules.podspec,
    **dict.fromkeys((".csproj", ".vbproj", ".fsproj", ".vcxproj", ".proj", ".props", ".targets"), xmlrules.msbuild),
}


def reader_kind(path: str) -> bool:
    """A file a detector reads by name (a manifest or build file), as opposed to a script it may only run."""
    name = PurePosixPath(path).name.lower()
    return name in WITH_TREE or name in WITH_PATH or name in TEXT_ONLY or name.endswith(tuple(BY_SUFFIX))


def read(path: str, text: str, writes: dict[str, str], root: str) -> list[Hit]:
    """The hooks one written file declares, plus, for a script or .rs file, whether a manifest runs it."""
    name = PurePosixPath(path).name.lower()
    hits = targets.npm_script(path, text, writes, root)
    if name.endswith(".rs") and name != "build.rs":
        hits += targets.cargo_build(path, text, writes, root)
    if name in WITH_TREE:
        return hits + WITH_TREE[name](path, text, writes, root)
    if name in WITH_PATH:
        return hits + WITH_PATH[name](path, text)
    reader = TEXT_ONLY.get(name) or next((r for suffix, r in BY_SUFFIX.items() if name.endswith(suffix)), None)
    return hits + (reader(text) if reader else [])
