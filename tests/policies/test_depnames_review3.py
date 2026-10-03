"""verify-dependency-exists: reader forms a third review found missed, each shown refused and silent."""

from __future__ import annotations

import time

import pytest
from policies import depkit

gate, r = depkit.load()


@pytest.mark.parametrize(
    "text",
    [
        "deps: &d\n  evil: ^1.0.0\ndependencies: *d\n",
        "dependencies:\n  a: ^1\ndependencies:\n  b: ^1\n",
        "dependencies:\n  <<: *x\n",
    ],
)
def test_a_pubspec_section_a_loader_may_resolve_elsewhere_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        r.dart.pubspec_names(text)


def test_a_plain_pubspec_is_read() -> None:
    assert r.dart.pubspec_names("dependencies:\n  http: ^1\ndev_dependencies:\n  lints: ^2\n") == ["http", "lints"]


@pytest.mark.parametrize(
    "line",
    [
        "implementation 'com.github.User:Repo:master-SNAPSHOT'",
        "implementation 'com.evil:lib:latest.release'",
        "implementation 'com.github.User:Repo:abcdef1'",
        'implementation(platform("com.evil:bom"))',
        "implementation enforcedPlatform('com.evil:bom')",
        "testFixturesApi 'com.evil:lib'",
        "implementation group: 'com.evil',\n    name: 'lib'",
    ],
)
def test_gradle_forms_the_review_found_are_read(line: str) -> None:
    expected = "com.github.User" if "github" in line else "com.evil"
    assert {name.split(":")[0] for name in r.gradle.gradle_names(line)} == {expected}


def test_gradle_still_ignores_projects_and_plain_strings() -> None:
    assert r.gradle.gradle_names("implementation project(':lib')\nprintln('a b:c')\n") == []


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("Gemfile.ci", "Gemfile"),
        ("gemfiles/rails7.gemfile", "Gemfile"),
        ("requirements/dev/base.txt", "requirements"),
        ("requirements-dev.pip", "requirements"),
        ("Gemfile.lock", "Gemfile.lock"),
    ],
)
def test_more_manifest_names_are_routed(path: str, kind: str) -> None:
    assert r.families.family(path).kind == kind


def test_a_gem_call_with_parentheses_after_other_code_is_read() -> None:
    assert r.ruby.gemfile_names("x = (gem 'evil')\ngem('also')\n") == ["evil", "also"]


def test_a_mix_hex_rename_names_the_real_package() -> None:
    assert r.elixir.mix_names('[{:local, "~> 1", hex: :real_pkg}, {:plain, "~> 1"}]') == ["real_pkg", "plain"]


def test_pyproject_tables_the_review_found_are_read() -> None:
    text = (
        "[tool.hatch.envs.t]\nextra-dependencies = ['hx']\n[tool.hatch.build.hooks.custom]\ndependencies = ['hh']\n"
        "[tool.poetry.requires-plugins]\nplug = '*'\n[tool.tox]\nrequires = ['tx>=1']\n"
    )
    assert r.pytoml.pyproject_names(text) == ["hx", "hh", "plug", "tx"]


def test_a_csproj_item_is_matched_without_regard_to_case() -> None:
    text = '<Project><ItemGroup><packagereference include="Evil"/></ItemGroup></Project>'
    assert r.dotnet.dotnet_names(text) == ["Evil"]


@pytest.mark.parametrize(
    ("reader", "text"),
    [
        ("ruby.gemfile_names", "gem" + " " * 60000),
        ("gradle.gradle_names", "implementation" + " " * 60000),
        ("pyreq.requirement_names", "a" + " " * 60000 + "x"),
    ],
)
def test_a_whitespace_run_is_linear(reader: str, text: str) -> None:
    module, name = reader.split(".")
    start = time.monotonic()
    getattr(getattr(r, module), name)(text)
    assert time.monotonic() - start < 5
