#!/usr/bin/env python3
"""Decide what a pull request must run: FULL, or the policies it touches and the test files that prove them.

    python tools/select_tests.py origin/main             # FULL, or one test file per line
    python tools/select_tests.py origin/main --policies  # FULL, or one policy id per line
    python tools/select_tests.py origin/main --matrix    # FULL, or JSON [{id, path, tests}] per policy job
    python tools/select_tests.py origin/main --residual  # FULL, or the test files no policy job owns

The changed files come from `git diff --name-only <base>...HEAD`. Only a change attributable to
named policies narrows the run; every other change is FULL. Unsure is FULL: an unreadable diff, an
unknown base, an empty diff, a path this tool has no rule for, a file under tests/ nothing imports.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

from trees import ROOT, TREES

FULL = "FULL"
#: A test helper imported (directly or through another helper) by this many test files is shared
#: across suites rather than one policy's kit, so changing it re-runs everything.
SHARED_IMPORTERS = 8
#: Applied to every test beside or below it, whoever imports it.
PACKAGE_WIDE = {"__init__.py", "conftest.py"}
#: A path with a space, quote or control character is a path no later step should be handed.
PLAIN_PATH = re.compile(r"[\w./+@-]+")
#: Tests that walk every policy have no single policy to attribute to.
WALKERS = re.compile(r"policy_dirs\(")
#: Cheap structural tests over the whole repo, run on every targeted run.
ALWAYS = {"tests/test_repo_standards.py"}
#: Tests of the code every policy shares (tools/, lib/): changing that is FULL, so they run then.
SHARED_CODE_TESTS = ("tests/build_tools/", "tests/chock_scan/", "tests/policies/test_shell")
#: Files tools/regen_all.py writes from the policies, so a policy change brings them along. The `generated`
#: job checks them on every PR; these are the tests that read the real ones.
DERIVED = {"registry.yaml", "README.md", "SECURITY.md", "CONTRIBUTING.md", "docs/policy-prose.yaml"}
DERIVED_READERS = ("tests/build_tools/test_gen_registry.py",)
#: Files a generator writes that no test reads and no policy owns: the images, and docs/quickstart.sh. The
#: `figures`, `brand-assets`, `generated` and `quickstart` jobs check them on every PR, so they need no test run.
GENERATED = {
    *(f"docs/assets/{name}" for name in ("coverage-matrix.svg", "logo.svg", "logo-512.png")),
    *(f"docs/assets/social-preview.{ext}" for ext in ("svg", "png")),
    *(f"docs/figures/{stem}-{theme}.svg" for stem in ("enforcement", "family") for theme in ("dark", "light")),
    *(f"docs/figures/social-card.{ext}" for ext in ("svg", "png")),
    "docs/quickstart.sh",
}
#: More policies than this is a change to the catalog's core; one balanced full run beats this many jobs.
MAX_POLICY_JOBS = 8
#: Folders whose tests are not one suite, so one that names no policy does not borrow from a neighbour.
MIXED_FOLDERS = ("tests/build_tools/", "tests/chock_scan/", "tests/policies/")


def git_lines(root: Path, *args: str) -> list[str]:
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    if proc.returncode:
        message = f"git {' '.join(args)}: {proc.stderr.strip()}"
        raise SystemExit(message)
    return proc.stdout.splitlines()


def changed_files(base: str, root: Path) -> list[str]:
    """What the PR changes: both sides of a rename, and nothing from the working tree."""
    return git_lines(root, "diff", "--name-only", "--no-renames", f"{base}...HEAD")


def policy_ids(root: Path) -> dict[str, Path]:
    return {
        p.name: p for tree in TREES if (root / tree).is_dir() for p in sorted((root / tree).iterdir()) if p.is_dir()
    }


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def own_names(policy: Path, lib: Path) -> set[str]:
    """What a test says when it means this policy: its id in either spelling, its scripts and packages.

    A package copied from lib/ sits in many policies, so it names none of them; neither does a
    folder of data, which is named for what it holds rather than for the policy.
    """
    skip = {p.name for p in lib.iterdir()} | {"data", "__pycache__"} if lib.is_dir() else set()
    impl = policy / "implementations"
    shipped = {Path(p.name).stem for p in impl.iterdir()} - skip if impl.is_dir() else set()
    return {policy.name, policy.name.replace("-", "_"), *shipped}


def import_graph(root: Path) -> dict[str, set[str]]:
    """Each Python file under tests/ -> the tests/ files it imports, by module stem."""
    files = {p.relative_to(root).as_posix(): p for p in sorted((root / "tests").rglob("*.py"))}
    stems: dict[str, set[str]] = {}
    for rel in files:
        stems.setdefault(Path(rel).stem, set()).add(rel)
    graph: dict[str, set[str]] = {}
    for rel, path in files.items():
        names: set[str] = set()
        for node in ast.walk(ast.parse(read(path))):
            if isinstance(node, ast.Import):
                names |= {part for alias in node.names for part in alias.name.split(".")}
            elif isinstance(node, ast.ImportFrom):
                names |= set((node.module or "").split(".")) | {alias.name for alias in node.names}
        graph[rel] = {dep for name in names for dep in stems.get(name, ()) if dep != rel}
    return graph


def reachable(graph: dict[str, set[str]], start: str) -> set[str]:
    seen: set[str] = set()
    todo = [start]
    while todo:
        for dep in graph[todo.pop()] - seen:
            seen.add(dep)
            todo.append(dep)
    return seen


def importers(graph: dict[str, set[str]]) -> dict[str, set[str]]:
    """Each file -> every file that reaches it by imports."""
    found: dict[str, set[str]] = {rel: set() for rel in graph}
    for rel in graph:
        for dep in reachable(graph, rel):
            found[dep].add(rel)
    return found


def is_test(rel: str) -> bool:
    return Path(rel).name.startswith("test_") and rel.endswith(".py")


def dependents(root: Path, touched: set[str]) -> set[str]:
    """The touched policies, plus every policy whose shipped files name one of them, transitively."""
    policies = policy_ids(root)
    named: dict[str, set[str]] = {}
    for pid, folder in policies.items():
        impl = folder / "implementations"
        text = "\n".join(read(f) for f in sorted(impl.rglob("*")) if f.is_file()) if impl.is_dir() else ""
        named[pid] = {other for other in policies if other != pid and other in text}
    out = set(touched)
    while grown := {pid for pid, uses in named.items() if uses & out} - out:
        out |= grown
    return out


def owners(root: Path) -> dict[str, set[str]]:
    """Each test file -> the policies it proves: named by its file name, its text, or a kit it imports.

    A test that names none borrows from its siblings when its folder is one policy's suite
    (tests/java_security), but not in a folder of mixed tests (tests/policies, shared code).
    """
    folders = policy_ids(root)
    graph = import_graph(root)
    back = importers(graph)
    names = {pid: own_names(folder, root / "lib") for pid, folder in folders.items()}
    found: dict[str, set[str]] = {}
    for rel in filter(is_test, graph):
        kits = [f for f in sorted(reachable(graph, rel)) if len(back[f]) < SHARED_IMPORTERS]
        text = "\n".join(read(root / f) for f in (rel, *kits))
        stem = Path(rel).stem
        found[rel] = {
            pid
            for pid, named in names.items()
            if stem.startswith("test_" + pid.replace("-", "_")) or any(n in text for n in named)
        }
        if WALKERS.search(read(root / rel)):
            found[rel] |= set(folders)
    named = {rel: set(hit) for rel, hit in found.items()}
    for rel, hit in found.items():
        if not hit and not rel.startswith(MIXED_FOLDERS):
            hit.update(*(named[other] for other in named if other.rpartition("/")[0] == rel.rpartition("/")[0]))
    return found


def unowned(root: Path) -> list[str]:
    """Tests that prove no policy and are not run always: they run on a FULL run, or when a change names them."""
    return sorted(rel for rel, hit in owners(root).items() if not hit and rel not in ALWAYS)


def proving_tests(root: Path, policies: set[str]) -> set[str]:
    """Every test file that proves one of `policies`."""
    return {rel for rel, hit in owners(root).items() if hit & policies}


def policy_of(rel: str, ids: set[str]) -> str | None:
    """The one policy a path belongs to: its own folder, or its generated docs."""
    top, _, rest = rel.partition("/")
    pid, _, tail = rest.partition("/")
    return pid if tail and pid in ids and (top in TREES or top == "docs") else None


def attribute(
    root: Path, rel: str, ids: set[str], graph: dict[str, set[str]], back: dict[str, set[str]]
) -> tuple[set[str], set[str]] | None:
    """What one changed file touches: (policies, test files it must run), or None when it is not attributable."""
    pid = policy_of(rel, ids)
    if not PLAIN_PATH.fullmatch(rel):
        return None
    if pid and (root / rel).is_file():
        return {pid}, set()
    readers = DERIVED_READERS if rel in DERIVED else () if rel in GENERATED and (root / rel).is_file() else None
    if readers is not None and all((root / reader).is_file() for reader in readers):
        return set(), set(readers)
    if is_test(rel) and rel in graph:
        return set(), {rel}
    if rel in graph and Path(rel).name not in PACKAGE_WIDE and 0 < len(back[rel]) < SHARED_IMPORTERS:
        return set(), {t for t in back[rel] if is_test(t)}
    return None


def touches(root: Path, files: list[str]) -> tuple[set[str], set[str]] | None:
    """(policies the files belong to, tests they name), or None when one is not attributable."""
    ids = set(policy_ids(root))
    graph = import_graph(root)
    back = importers(graph)
    touched: set[str] = set()
    tests: set[str] = set()
    for rel in files:
        found = attribute(root, rel, ids, graph, back)
        if found is None:
            return None
        touched |= found[0]
        tests |= found[1]
    return (touched, tests) if files else None


def select(root: Path, files: list[str]) -> tuple[bool, set[str], set[str]]:
    """(full, policies, tests): everything the change touches, or FULL when it is not all attributable."""
    found = touches(root, files)
    if found is None:
        return True, set(), set()
    covered = dependents(root, found[0])
    if len(covered) > MAX_POLICY_JOBS:
        return True, set(), set()
    return False, covered, found[1] | proving_tests(root, covered) | {t for t in ALWAYS if (root / t).is_file()}


def jobs(root: Path, policies: set[str]) -> list[dict]:
    """One job per policy: its id, its folder, and the test files that prove it."""
    folders, owned = policy_ids(root), owners(root)
    return [
        {
            "id": pid,
            "path": folders[pid].relative_to(root).as_posix(),
            "tests": sorted(rel for rel, hit in owned.items() if pid in hit),
        }
        for pid in sorted(policies)
    ]


def matrix(root: Path, files: list[str]) -> list[dict] | None:
    """The policy jobs a change needs, or None when the run is FULL."""
    full, policies, _ = select(root, files)
    return None if full else jobs(root, policies)


def residual(root: Path, files: list[str]) -> list[str] | None:
    """The selected test files no policy job owns: changed tests and the always-run ones; None when FULL."""
    full, policies, tests = select(root, files)
    return None if full else sorted(tests.difference(*(set(job["tests"]) for job in jobs(root, policies))))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", help="the ref the PR targets, e.g. origin/main")
    shape = parser.add_mutually_exclusive_group()
    shape.add_argument("--policies", action="store_true", help="print policy ids instead of test files")
    shape.add_argument("--matrix", action="store_true", help="print the policy jobs as JSON")
    shape.add_argument("--residual", action="store_true", help="print the test files no policy job owns")
    args = parser.parse_args(argv)
    try:
        files = changed_files(args.base, ROOT)
        if args.matrix:
            result = matrix(ROOT, files)
        elif args.residual:
            result = residual(ROOT, files)
        else:
            full, policies, tests = select(ROOT, files)
            result = None if full else sorted(policies if args.policies else tests)
    except (SystemExit, SyntaxError, OSError) as exc:
        print(f"{exc}; running everything.", file=sys.stderr)
        result = None
    if result is None:
        print(FULL)
    else:
        print(json.dumps(result) if args.matrix else "\n".join(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
