"""select_tests.py: a PR narrows to the policies it touches only when every changed file is attributable."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import select_tests
from select_tests import FULL, SHARED_CODE_TESTS, owners, policy_of, proving_tests, select, unowned

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


def test_policy_of_reads_a_policy_folder_or_its_generated_docs() -> None:
    ids = {"alpha", "beta"}
    assert policy_of("base/alpha/evals/suite.yaml", ids) == "alpha"
    assert policy_of("docs/beta/adoption.md", ids) == "beta"
    assert policy_of("base/alpha", ids) is None
    assert policy_of("base/README.md", ids) is None
    assert policy_of("base/unknown/manifest.yaml", ids) is None
    assert policy_of("tools/alpha/x.py", ids) is None
    assert policy_of("docs/other/page.md", ids) is None


def test_a_test_is_owned_by_the_policies_it_names_in_its_file_name_text_or_kit(tree: Path) -> None:
    found = owners(tree)
    assert found["tests/policies/test_alpha_cases.py"] == {"alpha"}
    assert found["tests/policies/test_names_beta.py"] == {"beta"}
    assert found["tests/policies/test_via_kit.py"] == {"gamma"}
    assert found["tests/policies/test_walks.py"] == {"alpha", "beta", "gamma"}
    assert found["tests/suite/test_names_alpha.py"] == {"alpha"}


def test_a_kit_imported_by_many_tests_is_shared_and_names_no_policy_for_them(tree: Path) -> None:
    assert owners(tree)[SHARED[0]] == set()


def test_a_test_naming_nothing_borrows_from_its_suite_but_not_from_shared_code(tree: Path) -> None:
    found = owners(tree)
    assert found["tests/suite/test_names_nothing.py"] == {"alpha"}
    assert found["tests/build_tools/test_names_nothing.py"] == set()
    assert found["tests/orphans/test_names_nothing.py"] == set()
    assert found["tests/policies/test_names_nothing.py"] == set()


def test_a_script_and_a_package_name_their_policy_but_lib_copies_and_data_do_not(tree: Path) -> None:
    write(tree, "tests/policies/test_gate_script.py", "run('alpha-gate')\n")
    write(tree, "tests/policies/test_lib_and_data.py", "chock_lib = table = data = 1\n")
    found = owners(tree)
    assert found["tests/policies/test_gate_script.py"] == {"alpha"}
    assert found["tests/policies/test_lib_and_data.py"] == set()


def test_unowned_lists_what_proves_no_policy(tree: Path) -> None:
    assert unowned(tree) == [
        "tests/build_tools/test_gen_registry.py",
        "tests/build_tools/test_names_nothing.py",
        "tests/orphans/test_names_nothing.py",
        "tests/policies/test_names_nothing.py",
        *SHARED,
    ]


def test_proving_tests_are_those_that_name_the_policy(tree: Path) -> None:
    assert proving_tests(tree, {"beta"}) == {"tests/policies/test_names_beta.py", "tests/policies/test_walks.py"}
    assert proving_tests(tree, {"gamma"}) >= {"tests/policies/test_via_kit.py", "tests/policies/test_walks.py"}
    assert proving_tests(tree, set()) == set()


def test_a_policy_change_runs_its_tests_and_those_of_the_policies_built_on_it(tree: Path) -> None:
    write(tree, "base/alpha/evals/suite.yaml")
    write(tree, "docs/alpha/adoption.md")
    full, policies, tests = select(tree, ["base/alpha/evals/suite.yaml", "docs/alpha/adoption.md"])
    assert (full, policies) == (False, {"alpha", "beta"})
    assert tests == proving_tests(tree, {"alpha", "beta"}) | {"tests/test_repo_standards.py"}
    assert "tests/policies/test_names_beta.py" in tests


def test_a_policy_nothing_builds_on_runs_alone(tree: Path) -> None:
    write(tree, "base/beta/evals/suite.yaml")
    assert select(tree, ["base/beta/evals/suite.yaml"])[1] == {"beta"}


def test_a_changed_test_runs_itself_and_nothing_else(tree: Path) -> None:
    assert select(tree, ["tests/suite/test_names_alpha.py"]) == (
        False,
        set(),
        {STANDARDS, "tests/suite/test_names_alpha.py"},
    )


def test_a_private_kit_runs_the_tests_that_import_it(tree: Path) -> None:
    assert select(tree, ["tests/policies/gammakit.py"]) == (False, set(), {STANDARDS, "tests/policies/test_via_kit.py"})
    assert select(tree, ["tests/suite/tokens.py"]) == (False, set(), {STANDARDS, "tests/policies/test_via_kit.py"})


@pytest.mark.parametrize("derived", ["registry.yaml", "README.md", "docs/policy-prose.yaml"])
def test_a_generated_file_runs_only_the_tests_that_read_it(tree: Path, derived: str) -> None:
    assert select(tree, [derived]) == (False, set(), {STANDARDS, "tests/build_tools/test_gen_registry.py"})
    assert select(tree, ["base/beta/manifest.yaml", derived])[1] == {"beta"}


def test_a_generated_file_is_full_when_its_reader_is_gone(tree: Path) -> None:
    (tree / "tests/build_tools/test_gen_registry.py").unlink()
    assert select(tree, ["registry.yaml"]) == (True, set(), set())


@pytest.mark.parametrize(
    "changed",
    [
        pytest.param([], id="empty diff"),
        pytest.param(["tests/policies/sharedkit.py"], id="kit shared by many suites"),
        pytest.param(["tests/policies/conftest.py"], id="conftest"),
        pytest.param(["tests/policies/__init__.py"], id="package init"),
        pytest.param(["tests/policies/loose.py"], id="helper nothing imports"),
        pytest.param(["tests/policies/test_gone.py"], id="deleted test"),
        pytest.param(["base/alpha/implementations/gone.py"], id="deleted policy file"),
        pytest.param(["base/README.md"], id="file in a tree but no policy"),
        pytest.param(["docs/other/page.md"], id="docs of no policy"),
        pytest.param(["lib/chock_lib/__init__.py"], id="shared lib"),
        pytest.param(["tools/trees.py"], id="shared tool"),
        pytest.param(["pyproject.toml"], id="config"),
        pytest.param([".github/workflows/ci.yml"], id="workflow"),
        pytest.param(["tests/data/corpus.txt"], id="test data"),
        pytest.param(["base/alpha/manifest.yaml", "pyproject.toml"], id="one policy and one shared file"),
        pytest.param(["base/alpha/evals/my suite.yaml"], id="a space in the path"),
        pytest.param(['"base/alpha/caf\\303\\251.yaml"'], id="a path git had to quote"),
    ],
)
def test_anything_not_attributable_to_policies_is_full(tree: Path, changed: list[str]) -> None:
    assert select(tree, changed) == (True, set(), set())


def test_the_catalog_has_no_test_that_proves_no_policy_outside_shared_code() -> None:
    """A new test that names no policy would run only on main; this fails until it does."""
    assert [rel for rel in unowned(select_tests.ROOT) if not rel.startswith(SHARED_CODE_TESTS)] == []


def test_the_catalog_has_a_reader_for_each_generated_file() -> None:
    """The readers are named, not found: this fails if one is renamed or stops reading what it is named for."""
    for reader in select_tests.DERIVED_READERS:
        text = (select_tests.ROOT / reader).read_text(encoding="utf-8")
        assert all(Path(name).name in text for name in ("registry.yaml", "README.md")), reader


def test_the_catalog_narrows_a_policy_change_and_widens_shared_code() -> None:
    root = select_tests.ROOT
    full, policies, tests = select(root, ["base/git-safety/evals/suite.yaml"])
    assert (full, "git-safety" in policies, "tests/policies/test_every_policy.py" in tests) == (False, True, True)
    assert select(root, ["tests/policies/guardkit.py"])[0]
    assert select(root, ["tools/gen_registry.py"])[0]


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


def test_changed_files_is_the_diff_against_the_merge_base_with_both_sides_of_a_rename(repo: Path) -> None:
    git(repo, "mv", "tests/suite/tokens.py", "tests/suite/words.py")
    git(repo, "commit", "-qm", "rename")
    write(repo, "untracked.txt")
    assert select_tests.changed_files("main", repo) == ["tests/suite/tokens.py", "tests/suite/words.py"]


def test_a_bad_ref_is_an_error(repo: Path) -> None:
    with pytest.raises(SystemExit, match="no-such-ref"):
        select_tests.changed_files("no-such-ref", repo)


def test_main_prints_the_test_files_or_the_policy_ids(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    commit(repo, "base/beta/evals/suite.yaml", "x\n")
    assert select_tests.main(["main"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "tests/policies/test_names_beta.py",
        "tests/policies/test_walks.py",
        "tests/test_repo_standards.py",
    ]
    assert select_tests.main(["main", "--policies"]) == 0
    assert capsys.readouterr().out.splitlines() == ["beta"]


def test_main_prints_full_when_shared_code_changes(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    commit(repo, "pyproject.toml", "[tool]\n")
    assert select_tests.main(["main"]) == 0
    assert capsys.readouterr().out.strip() == FULL


@pytest.mark.parametrize("fault", ["unknown base", "unparsable test"])
def test_main_prints_full_whenever_it_cannot_tell(repo: Path, capsys: pytest.CaptureFixture[str], fault: str) -> None:
    base = "main"
    if fault == "unknown base":
        base = "no-such-ref"
    else:
        commit(repo, "tests/policies/test_broken.py", "def (:\n")
    assert select_tests.main([base]) == 0
    out = capsys.readouterr()
    assert out.out.strip() == FULL
    assert "running everything" in out.err


def test_run_as_a_script_it_answers_full_for_a_base_it_cannot_find() -> None:
    proc = subprocess.run(
        [sys.executable, str(Path(select_tests.__file__)), "no-such-ref"], capture_output=True, text=True, check=True
    )
    assert proc.stdout.strip() == FULL
