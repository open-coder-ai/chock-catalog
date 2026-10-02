"""lockfile-integrity: a lock and its manifest moving together, and locks ignored or deleted."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies.lockkit import BASE_LOCK, BASE_MANIFEST, manifest, model, sync


@pytest.mark.parametrize(
    ("path", "lock", "man"),
    [
        ("a/Package-Lock.json", "npm", None),
        ("go.sum", "go", None),
        ("x/app.CSPROJ", None, "nuget"),
        ("Pipfile", None, "pipenv"),
        ("README.md", None, None),
    ],
)
def test_names_map_to_ecosystems_without_case(path: str, lock: str | None, man: str | None) -> None:
    assert (sync.lock_eco(path), sync.manifest_eco(path)) == (lock, man)


def test_related_means_one_folder_holds_the_other() -> None:
    assert sync.related("package-lock.json", "packages/a/package.json")
    assert sync.related("a/b/packages.lock.json", "Directory.Packages.props")
    assert not sync.related("a/package-lock.json", "b/package.json")


@pytest.mark.parametrize(
    ("path", "before", "after", "same"),
    [
        ("package.json", BASE_MANIFEST, manifest({"left-pad": "^1.3.0"}, scripts={"t": "x"}), True),
        ("package.json", BASE_MANIFEST, manifest({"left-pad": "^2.0.0"}), False),
        ("pyproject.toml", '[project]\nname = "a"\n', '[project]\nname = "a"\n[tool.ruff]\nx = 1\n', True),
        ("pyproject.toml", '[project]\ndependencies = ["a"]\n', '[project]\ndependencies = ["b"]\n', False),
        ("Cargo.toml", '[package]\nversion = "1"\n', '[package]\nversion = "2"\n', False),
        ("go.mod", "module a\n\ngo 1.21\n", "module a\n\ngo 1.22\n", True),
        ("go.mod", "module a\nrequire (\n  x v1 // c\n)\n", "module a\nrequire (\n  x v2\n)\n", False),
        ("a.gemspec", 's.summary = "a"\ns.add_dependency "x"\n', 's.summary = "b"\ns.add_dependency "x"\n', True),
        (
            "app.csproj",
            "<Project>\n</Project>\n",
            '<Project>\n<PackageReference Include="A" Version="1" />\n</Project>\n',
            False,
        ),
        ("app.csproj", "<Project><A/></Project>", "<Project><B/></Project>", True),
        ("Gemfile", "# c\ngem 'a'\n", "# d\ngem 'a'\n", True),
        ("package.json", "{", "{ ", False),
        ("composer.json", '{"require": {"a": "1"}}', '{"require": {"a": "1"}, "name": "x"}', True),
    ],
)
def test_dependency_digest_moves_only_with_dependencies(path: str, before: str, after: str, same: bool) -> None:
    assert (sync.dependency_digest(path, before) == sync.dependency_digest(path, after)) is same


def test_lock_on_disk_walks_up_to_the_root(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    assert sync.lock_on_disk(tmp_path, "pkg/package.json", "npm")
    assert not sync.lock_on_disk(tmp_path, "pkg/Cargo.toml", "cargo")
    assert not sync.lock_on_disk(tmp_path, "/elsewhere/package.json", "npm")


def test_sync_findings_ask_for_a_lock_or_a_manifest_moved_alone(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(BASE_LOCK, encoding="utf-8")
    alone = sync.sync_findings({"package-lock.json": BASE_LOCK}, tmp_path)
    assert [f.rule for f in alone] == [model.LOCK_ONLY]
    manifest_only = sync.sync_findings({"package.json": BASE_MANIFEST}, tmp_path)
    assert [f.rule for f in manifest_only] == [model.MANIFEST_ONLY]
    assert sync.sync_findings({"package.json": BASE_MANIFEST, "package-lock.json": BASE_LOCK}, tmp_path) == []
    assert sync.sync_findings({"Cargo.toml": "[package]\n"}, tmp_path) == []


def test_ignore_findings_need_a_manifest_beside_the_ignored_lock(tmp_path: Path) -> None:
    (tmp_path / "cache").mkdir()
    (tmp_path / "package.json").write_text(BASE_MANIFEST, encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(BASE_LOCK, encoding="utf-8")
    text = "# locks\n!keep.lock\n\nnode_modules/\n/package-lock.json\n**/Cargo.lock\n"
    got = sync.ignore_findings({".gitignore": text}, tmp_path)
    assert [(f.rule, f.line) for f in got] == [(model.IGNORED, 5)]
    assert sync.ignore_findings({"cache/.gitignore": "*\n"}, tmp_path) == []
    with_cargo = sync.ignore_findings({".gitignore": text, "Cargo.toml": "[package]\n", "Cargo.lock": ""}, tmp_path)
    assert [f.line for f in with_cargo] == [5, 6]
    assert sync.ignore_findings({"/outside/.gitignore": "yarn.lock\n", "README.md": "x"}, tmp_path) == []
    # ignoring another package manager's lock keeps a project to one; only a lock the folder holds counts
    assert sync.ignore_findings({".gitignore": "yarn.lock\npnpm-lock.yaml\n"}, tmp_path) == []


def test_deleted_findings_need_the_manifest_to_stay(tmp_path: Path) -> None:
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(BASE_MANIFEST, encoding="utf-8")
    got = sync.deleted_findings(["web/yarn.lock", "gone/Cargo.lock", "README.md", "go.sum"], tmp_path)
    assert [(f.rule, f.path) for f in got] == [(model.DELETED, "web/yarn.lock")]
