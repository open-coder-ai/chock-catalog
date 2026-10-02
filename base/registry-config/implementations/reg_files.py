"""Which reader judges a written file, chosen by its name (any folder, any case)."""

from __future__ import annotations

import re
from collections.abc import Callable

import reg_bots
import reg_cargo
import reg_go
import reg_misc
import reg_npm
import reg_python
import reg_xml
from reg_core import Ctx

Reader = Callable[[Ctx], None]

BY_NAME: dict[str, Reader] = {
    ".npmrc": reg_npm.npmrc,
    "npmrc": reg_npm.npmrc,
    ".yarnrc": reg_npm.yarnrc,
    ".yarnrc.yml": reg_npm.yarnrc_yml,
    ".yarnrc.yaml": reg_npm.yarnrc_yml,
    "pnpm-workspace.yaml": reg_npm.pnpm_workspace,
    "pnpm-workspace.yml": reg_npm.pnpm_workspace,
    ".pnpmfile.cjs": reg_npm.pnpmfile,
    ".pnpmfile.mjs": reg_npm.pnpmfile,
    "pnpmfile.js": reg_npm.pnpmfile,
    "bunfig.toml": reg_npm.bunfig,
    ".bunfig.toml": reg_npm.bunfig,
    "pip.conf": reg_python.pip_conf,
    "pip.ini": reg_python.pip_conf,
    "uv.toml": reg_python.uv_toml,
    "pyproject.toml": reg_python.pyproject,
    ".pypirc": reg_python.pypirc,
    "pipfile": reg_python.pipfile,
    ".condarc": reg_python.condarc,
    "condarc": reg_python.condarc,
    "environment.yml": reg_python.condarc,
    "environment.yaml": reg_python.condarc,
    "go.mod": reg_go.gomod,
    "go.work": reg_go.gomod,
    "go.env": reg_go.go_env,
    "deny.toml": reg_cargo.deny_toml,
    "nuget.config": reg_xml.nuget,
    "directory.build.props": reg_xml.props,
    "directory.build.targets": reg_xml.props,
    "settings.xml": reg_xml.maven,
    "gemfile": reg_misc.gemfile,
    "gems.rb": reg_misc.gemfile,
    "composer.json": reg_misc.composer,
    "mix.exs": reg_misc.mix,
    "podfile": reg_misc.podfile,
    "package.swift": reg_misc.swift,
    "renovate.json": reg_bots.renovate,
    "renovate.json5": reg_bots.renovate,
    ".renovaterc": reg_bots.renovate,
    ".renovaterc.json": reg_bots.renovate,
    ".renovaterc.json5": reg_bots.renovate,
}

#: (pattern on the lower-cased path, reader), tried in order when the name alone does not decide.
BY_PATH: tuple[tuple[re.Pattern[str], Reader], ...] = (
    (re.compile(r"(?:^|/)\.cargo/config(?:\.toml)?$"), reg_cargo.cargo_config),
    (re.compile(r"(?:^|/)\.github/dependabot\.ya?ml$"), reg_bots.dependabot),
    (
        re.compile(
            r"(?:^|/)(?:[^/]*requirements[^/]*|constraints[^/]*)\.(?:txt|in)$|(?:^|/)requirements/[^/]+\.(?:txt|in)$"
        ),
        reg_python.requirements,
    ),
    # Where GO* module settings are written for a build: container, make, env and CI files.
    (
        re.compile(
            r"(?:^|/)(?:(?:docker|container)file[^/]*|[^/]+\.dockerfile|makefile|gnumakefile|[^/]+\.mk|\.env(?:\.[^/]*)?"
            r"|[^/]+\.env|\.envrc|jenkinsfile|\.gitlab-ci\.ya?ml|bitbucket-pipelines\.ya?ml|azure-pipelines[^/]*\.ya?ml"
            r"|\.travis\.ya?ml|\.drone\.ya?ml|cloudbuild[^/]*\.ya?ml|buildspec[^/]*\.ya?ml|action\.ya?ml)$"
            r"|(?:^|/)\.github/workflows/[^/]+\.ya?ml$|(?:^|/)\.circleci/[^/]+\.ya?ml$|(?:^|/)\.buildkite/[^/]+\.ya?ml$"
        ),
        reg_go.go_env,
    ),
)


def reader_for(path: str) -> Reader | None:
    """The reader for a repository path, or None when the file holds no registry settings this gate reads."""
    low = path.replace("\\", "/").lower()
    name = low.rsplit("/", 1)[-1]
    if name in BY_NAME:
        return BY_NAME[name]
    return next((reader for pattern, reader in BY_PATH if pattern.search(low)), None)
