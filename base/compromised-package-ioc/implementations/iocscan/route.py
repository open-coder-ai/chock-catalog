"""Which reader a path gets, and the `uses:` references of workflow and action files."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import PurePosixPath

from iocscan import Hit, npm, others, python

Reader = Callable[[str], Iterator[Hit]]
BY_NAME: dict[str, Reader] = {
    "package.json": npm.package_json,
    "package-lock.json": npm.package_lock,
    "npm-shrinkwrap.json": npm.package_lock,
    "yarn.lock": npm.yarn_lock,
    "pnpm-lock.yaml": npm.pnpm_lock,
    "bun.lock": npm.bun_lock,
    "pyproject.toml": python.pyproject,
    "pipfile": python.pipfile,
    "pipfile.lock": python.pipfile_lock,
    "poetry.lock": python.toml_lock,
    "uv.lock": python.toml_lock,
    "pdm.lock": python.toml_lock,
    "go.mod": others.go_mod,
    "go.sum": others.go_sum,
    "cargo.toml": others.cargo_toml,
    "cargo.lock": partial(others.toml_lock, "crates"),
    "gemfile": others.gemfile,
    "gems.rb": others.gemfile,
    "gemfile.lock": others.gemfile_lock,
    "gems.locked": others.gemfile_lock,
    "composer.json": others.composer_json,
    "composer.lock": others.composer_lock,
}
REQUIREMENTS = re.compile(r"(?:requirements|constraints)[^/]*\.(?:txt|in)")
WORKFLOW = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$")
USES = re.compile(r"""^[ \t]*(?:-[ \t]*)?['"]?uses['"]?[ \t]*:[ \t]*['"]?([^'"\s#]+)""", re.MULTILINE)


def reader(path: str) -> Reader | None:
    """The package reader for a path, by its file name (case folded, as a case-insensitive disk would find it)."""
    pure = PurePosixPath(path.casefold())
    if found := BY_NAME.get(pure.name):
        return found
    if pure.suffix == ".gemspec":
        return others.gemfile
    in_folder = pure.parent.name == "requirements" and pure.suffix in (".txt", ".in")
    return python.requirements if in_folder or REQUIREMENTS.fullmatch(pure.name) else None


def is_workflow(path: str) -> bool:
    """A GitHub workflow, or an action's own action.yml (composite actions call others with `uses:`)."""
    folded = path.casefold()
    return bool(WORKFLOW.search(folded)) or PurePosixPath(folded).name in ("action.yml", "action.yaml")


def uses(text: str) -> Iterator[tuple[str, str, int]]:
    """(owner/repo, ref, line) for every remote `uses:`; local `./` paths and `docker://` images are not actions."""
    for found in USES.finditer(text):
        value = found.group(1)
        if value.startswith(("./", "docker://")):
            continue
        target, _, ref = value.rpartition("@") if "@" in value else (value, "", "")
        yield "/".join(target.split("/")[:2]), ref, text.count("\n", 0, found.start(1)) + 1
