"""Fixtures for the selector tests: a two-policy catalog on disk, and the same as a git repo on a branch."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import select_tests

GIT = shutil.which("git") or "git"
STANDARDS = "tests/test_repo_standards.py"
SHARED = [f"tests/policies/test_use_shared_{n}.py" for n in range(select_tests.SHARED_IMPORTERS)]


def write(root: Path, rel: str, text: str = "x = 1\n") -> None:
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text, encoding="utf-8")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """Two policies (beta's script names alpha), a lib package, and a test of each kind."""
    write(tmp_path, "base/alpha/manifest.yaml")
    write(tmp_path, "base/alpha/implementations/alpha-gate.py")
    write(tmp_path, "base/alpha/implementations/chock_lib/__init__.py")
    write(tmp_path, "base/alpha/implementations/data/table.json")
    write(tmp_path, "base/beta/manifest.yaml")
    write(tmp_path, "base/beta/implementations/beta_core.py", "# built on alpha\n")
    write(tmp_path, "compliance/gamma/manifest.yaml")
    write(tmp_path, "docs/alpha/README.md")
    write(tmp_path, "docs/other/page.md")
    write(tmp_path, "lib/chock_lib/__init__.py")
    write(tmp_path, "tests/test_repo_standards.py")
    for pkg in ("policies", "suite", "build_tools", "orphans"):
        write(tmp_path, f"tests/{pkg}/__init__.py", "")
    write(tmp_path, "tests/policies/conftest.py")
    write(tmp_path, "tests/policies/test_alpha_cases.py")
    write(tmp_path, "tests/policies/test_names_beta.py", 'POLICY = "beta"\n')
    write(tmp_path, "tests/policies/test_via_kit.py", "import gammakit\nfrom suite import tokens\nimport os.path\n")
    write(tmp_path, "tests/policies/gammakit.py", "GUARDED = 'gamma'\n")
    write(tmp_path, "tests/policies/test_walks.py", "def test() -> None:\n    policy_dirs()\n")
    write(tmp_path, "tests/policies/sharedkit.py", "BETA_IN_A_KIT_EVERYONE_USES = 'beta'\n")
    write(tmp_path, "tests/policies/loose.py")
    for rel in SHARED:
        write(tmp_path, rel, "import sharedkit\n")
    write(tmp_path, "tests/suite/test_names_alpha.py", 'POLICY = "alpha"\n')
    write(tmp_path, "tests/suite/test_names_nothing.py")
    write(tmp_path, "tests/suite/tokens.py")
    write(tmp_path, "tests/build_tools/test_names_nothing.py")
    write(tmp_path, "tests/build_tools/test_gen_registry.py")
    for derived in ("registry.yaml", "README.md", "docs/policy-prose.yaml"):
        write(tmp_path, derived)
    write(tmp_path, "tests/orphans/test_names_nothing.py")
    write(tmp_path, "tests/policies/test_names_nothing.py")
    return tmp_path


def git(repo: Path, *args: str) -> None:
    subprocess.run([GIT, "-c", "commit.gpgsign=false", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tree: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    git(tree, "init", "-q", "-b", "main")
    git(tree, "config", "user.email", "t@chock.invalid")
    git(tree, "config", "user.name", "t")
    git(tree, "add", ".")
    git(tree, "commit", "-qm", "base")
    git(tree, "checkout", "-qb", "work")
    monkeypatch.setattr(select_tests, "ROOT", tree)
    return tree


def commit(repo: Path, rel: str, text: str) -> None:
    write(repo, rel, text)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", rel)
