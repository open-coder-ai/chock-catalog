"""Python TOML manifests: pyproject.toml (PEP 621, build-system, dependency groups, Poetry, uv, PDM) and Pipfile."""

from __future__ import annotations

import tomllib

from depnames.pyreq import requirement_names


def _table(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _specs(value: object) -> list[str]:
    """Names in a list of PEP 508 strings; include-group tables and other non-strings are skipped."""
    items = value if isinstance(value, list) else []
    return [name for item in items if isinstance(item, str) for name in requirement_names(item)]


def _keys(value: object) -> list[str]:
    """Table keys that are packages: Poetry names the interpreter under the same table."""
    return [key for key in _table(value) if key.lower() != "python"]


def pyproject_names(text: str) -> list[str]:
    """Every dependency name a pyproject.toml declares, in any of the tables tools read."""
    data = tomllib.loads(text.removeprefix("\ufeff"))
    project = _table(data.get("project"))
    names = _specs(project.get("dependencies")) + _specs(_table(data.get("build-system")).get("requires"))
    for extra in _table(project.get("optional-dependencies")).values():
        names += _specs(extra)
    for group in _table(data.get("dependency-groups")).values():
        names += _specs(group)
    tool = _table(data.get("tool"))
    poetry = _table(tool.get("poetry"))
    names += _keys(poetry.get("dependencies")) + _keys(poetry.get("dev-dependencies"))
    for group in _table(poetry.get("group")).values():
        names += _keys(_table(group).get("dependencies"))
    names += _specs(_table(tool.get("uv")).get("dev-dependencies"))
    for group in _table(_table(tool.get("pdm")).get("dev-dependencies")).values():
        names += _specs(group)
    return names


def pipfile_names(text: str) -> list[str]:
    """Package names of a Pipfile's [packages] and [dev-packages]."""
    data = tomllib.loads(text.removeprefix("\ufeff"))
    return _keys(data.get("packages")) + _keys(data.get("dev-packages"))
