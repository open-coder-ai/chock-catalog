"""compromised-package-ioc: what each PyPI reader lists."""

from __future__ import annotations

import json

import pytest
from policies.iockit import iocscan, python


def pairs(hits: object) -> list[tuple[str, str | None]]:
    return [(h.name, h.version) for h in hits]


@pytest.mark.parametrize(
    ("requirement", "want"),
    [
        ("litellm==1.82.7", ("litellm", "1.82.7")),
        ("LiteLLM[proxy] === 1.82.8 ; python_version > '3.8'", ("LiteLLM", "1.82.8")),
        ("litellm (==1.82.7)", ("litellm", "1.82.7")),
        ("litellm>=1.0,==1.82.7", ("litellm", "1.82.7")),
        ("litellm==1.82.*", ("litellm", None)),
        ("litellm>=1.82", ("litellm", None)),
        ("litellm @ https://example.org/l.whl", ("litellm", None)),
        ("litellm", ("litellm", None)),
        ("!!", None),
    ],
)
def test_pep508(requirement: str, want: tuple[str, str | None] | None) -> None:
    assert python.pep508(requirement) == want


def test_requirements_skip_options_comments_and_join_continuations() -> None:
    text = (
        "# pinned\n-r base.txt\n--index-url https://example.org\n-e git+https://x#egg=litellm\n\n"
        "ultralytics==8.3.41  # bad\nlitellm==1.82.8 \\\n    --hash=sha256:00\nrequests>=2\n!!\n"
    )
    assert pairs(python.requirements(text)) == [("ultralytics", "8.3.41"), ("litellm", "1.82.8"), ("requests", None)]


@pytest.mark.parametrize(
    ("spec", "want"),
    [
        ("8.3.41", "8.3.41"),
        ("==8.3.41", "8.3.41"),
        ("=8.3.41", "8.3.41"),
        ({"version": "8.3.41", "extras": ["x"]}, "8.3.41"),
        ({"git": "https://example.org/x"}, None),
        ("^8.3", None),
        ("*", None),
        (8, None),
    ],
)
def test_poetry_exact(spec: object, want: str | None) -> None:
    assert python.poetry_exact(spec) == want


def test_pyproject_reads_every_declaration_style() -> None:
    text = """
[build-system]
requires = ["setuptools", "telnyx==4.87.1"]
[project]
dependencies = ["litellm==1.82.7", 3]
[project.optional-dependencies]
proxy = ["litellm==1.82.8"]
skipped = "not a list"
[dependency-groups]
dev = ["ultralytics==8.3.42", {include-group = "x"}]
[tool.pdm.dev-dependencies]
lint = ["ultralytics==8.3.45"]
[tool.uv]
dev-dependencies = ["ultralytics==8.3.46"]
override-dependencies = ["telnyx==4.87.2"]
[tool.poetry.dependencies]
python = "^3.11"
litellm = [{version = "1.82.7", python = "<3.12"}, {version = "1.82.8", python = ">=3.12"}]
[tool.poetry.dev-dependencies]
ultralytics = "==8.3.41"
[tool.poetry.group.ci.dependencies]
telnyx = {version = "4.87.1"}
[tool.poetry.group.bad]
"""
    got = pairs(python.pyproject(text))
    for want in [
        ("telnyx", "4.87.1"),
        ("litellm", "1.82.7"),
        ("litellm", "1.82.8"),
        ("ultralytics", "8.3.42"),
        ("ultralytics", "8.3.45"),
        ("ultralytics", "8.3.46"),
        ("telnyx", "4.87.2"),
        ("ultralytics", "8.3.41"),
        ("setuptools", None),
        ("python", None),
    ]:
        assert want in got


def test_pyproject_with_odd_shapes_names_nothing() -> None:
    assert pairs(python.pyproject('project = "x"\n[tool]\npoetry = 1\n[tool.uv]\ndev-dependencies = 3\n')) == []
    assert pairs(python.pyproject("[tool.poetry]\ngroup = 1\n")) == []


def test_pipfile_reads_package_tables_and_skips_settings() -> None:
    text = (
        '[[source]]\nurl = "https://pypi.org/simple"\n[requires]\npython_version = "3.12"\n'
        '[packages]\nlitellm = "==1.82.7"\nrequests = "*"\n[dev-packages]\nultralytics = {version = "==8.3.41"}\n'
        '[scripts]\nx = "y"\n'
    )
    assert pairs(python.pipfile(text)) == [("litellm", "1.82.7"), ("requests", None), ("ultralytics", "8.3.41")]


def test_toml_locks_read_each_package() -> None:
    text = '[[package]]\nname = "litellm"\nversion = "1.82.8"\n\n[[package]]\nname = "x"\nversion = 3\n\n[[package]]\nversion = "1"\n'
    assert pairs(python.toml_lock(text)) == [("litellm", "1.82.8"), ("x", None)]
    assert pairs(python.toml_lock('package = "x"\n')) == []
    assert pairs(python.toml_lock("package = [1]\n")) == []


def test_pipfile_lock_reads_every_category() -> None:
    doc = {"_meta": {"hash": {}}, "default": {"telnyx": {"version": "==4.87.2"}}, "develop": {"x": {}}, "odd": []}
    assert pairs(python.pipfile_lock(json.dumps(doc))) == [("telnyx", "4.87.2"), ("x", None)]


@pytest.mark.parametrize(
    ("reader", "text"),
    [
        (python.pyproject, "[project\n"),
        (python.pipfile, "= 1\n"),
        (python.toml_lock, "[[package]\n"),
        (python.pipfile_lock, "{"),
        (python.pipfile_lock, "[]"),
    ],
)
def test_an_unreadable_file_is_unparseable(reader: object, text: str) -> None:
    with pytest.raises(iocscan.UnparseableError):
        list(reader(text))
