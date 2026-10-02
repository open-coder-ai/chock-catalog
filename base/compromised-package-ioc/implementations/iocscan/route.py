"""Which reader a path gets, and the `uses:` references of workflow and action files."""

from __future__ import annotations

import re
from collections import Counter
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
REQUIREMENTS = re.compile(r"[^/]*(?:requirements|constraints)[^/]*\.(?:txt|in|pip)")
WORKFLOW = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$")
USES = re.compile(r"""[ \t]*(?:-[ \t]*)?['"]?uses['"]?[ \t]*:(.*)""")
PLAIN = re.compile(r"[A-Za-z0-9_./-]+(?:@[A-Za-z0-9_./+-]*)?")
BLOCK_SCALAR = re.compile(r"[>|][-+]?")
#: Every `&name` in the text, comments and scalars included: an alias resolves only when its name occurs once.
ANCHOR_TOKEN = re.compile(r"&([^\s\[\]{},]+)")
#: An anchor in value position (`key: &name value` or `- &name value`) with its value on the same line.
VALUE_ANCHOR = re.compile(r"[ \t]*(?:-[ \t]+)?(?:[^#\s'\"][^#'\"]*?:[ \t]+)?&([^\s\[\]{},]+)[ \t]+([^\s#][^\n]*)")


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


def _value(raw: str) -> str:
    """A `uses:` value with its comment, YAML tags and anchor dropped and plain quotes removed."""
    value = re.split(r"\s#", raw, maxsplit=1)[0].strip()
    while value[:1] in ("!", "&"):
        value = value.partition(" ")[2].strip()
    if len(value) > 1 and value[0] == value[-1] and value[0] in "'\"" and "\\" not in value and "''" not in value[1:-1]:
        value = value[1:-1]
    return value


def uses(text: str) -> Iterator[tuple[str | None, str, int]]:
    """(owner/repo, ref, line) for every remote `uses:`, or (None, value, line) for one written in a form not read
    here (an alias whose name is not one value-position anchor with its value inline, an escaped string); local `./` paths and `docker://` images are not actions."""
    lines = text.splitlines()
    seen = Counter(ANCHOR_TOKEN.findall(text))
    anchors = {m.group(1): _value(m.group(2)) for line in lines if (m := VALUE_ANCHOR.fullmatch(line))}
    for number, line in enumerate(lines, 1):
        if not (found := USES.fullmatch(line)):
            continue
        value = _value(found.group(1))
        if not value or BLOCK_SCALAR.fullmatch(value):
            value = next((_value(rest) for rest in lines[number:] if rest.strip()), "")
        if value.startswith("*") and seen[value[1:]] == 1 and value[1:] in anchors:
            value = anchors[value[1:]]  # an alias runs what its one anchor names; any other `&name` is not read
        if value.startswith(("./", "docker://")):
            continue
        if not PLAIN.fullmatch(value):
            yield None, value, number
            continue
        target, _, ref = value.rpartition("@") if "@" in value else (value, "", "")
        yield "/".join(target.split("/")[:2]), ref, number
