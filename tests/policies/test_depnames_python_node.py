"""verify-dependency-exists: the Python, Node, Rust, Ruby and PHP readers return the names they should, and only those."""

from __future__ import annotations

import configparser

import pytest
from policies import depkit

_, r = depkit.load()
norm = r.norm
pyreq = r.pyreq
pytoml = r.pytoml
node = r.node
rust = r.rust
ruby = r.ruby
php = r.php


def names(reader, text: str) -> list[str]:
    return sorted(reader(text))


@pytest.mark.parametrize(
    ("eco", "raw", "expected"),
    [
        ("py", "Foo_Bar", "foo-bar"),
        ("py", "foo.bar__baz", "foo-bar-baz"),
        ("cargo", "Serde_JSON", "serde-json"),
        ("npm", "@Scope/Pkg", "@scope/pkg"),
        ("npm", "left_pad", "left_pad"),
        ("gem", " Rails ", "rails"),
    ],
)
def test_normalisation_follows_each_ecosystem(eco: str, raw: str, expected: str) -> None:
    assert norm.normalize(eco, raw) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("requests==2.0\nflask>=1,<3\n", ["flask", "requests"]),
        ("\ufeffrequests\r\nflask\r\n", ["flask", "requests"]),
        ("requests[security]>=2 ; python_version < '3.9'\n", ["requests"]),
        ("requests @ https://example.com/r.zip\n", ["requests"]),
        ("# comment\n\nrequests  # trailing\n", ["requests"]),
        ("requests==2.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nflask\n", ["flask", "requests"]),
        (
            "-i https://pypi.example/simple\n--extra-index-url https://x\n--find-links dist\n-r other.txt\nrequests\n",
            ["requests"],
        ),
        (
            "-e git+https://github.com/a/b.git#egg=bee\n--editable git+https://github.com/a/c.git#egg=sea\n",
            ["bee", "sea"],
        ),
        ("-e .\n-e ./pkg\n-e /abs/pkg\n-e file:///x\n", []),
        ("git+https://user:tok@github.com/a/b.git\n", ["git+https://github.com/a/b.git"]),
        ("https://example.com/pkg.tar.gz#egg=named\n", ["named"]),
        ("./local.whl\n../dist/x.zip\nfile:///x.whl\nfoo-1.0.tar.gz\n", []),
        ("two words\nfile: x\n", []),
        ("requests==1 \\\n", ["requests"]),
    ],
)
def test_requirement_files(text: str, expected: list[str]) -> None:
    assert names(pyreq.requirement_names, text) == expected


def test_includes_are_listed_as_written() -> None:
    text = "-r base.txt\n--requirement=../x.txt\n-c cons.txt\n--constraint cons2.txt\nrequests\n"
    assert pyreq.includes(text) == ["base.txt", "../x.txt", "cons.txt", "cons2.txt"]


def test_setup_cfg_reads_install_setup_tests_and_extras() -> None:
    cfg = (
        "[metadata]\nname = app\n[options]\npython_requires = >=3.9\ninstall_requires =\n    requests>=2\n    file: reqs.txt\n"
        "setup_requires = wheel\ntests_require =\n    pytest\n[options.extras_require]\ndocs =\n    sphinx\nall = a ; b\n"
    )
    assert names(pyreq.setup_cfg_names, cfg) == ["a", "pytest", "requests", "sphinx", "wheel"]
    assert pyreq.setup_cfg_names("[metadata]\nname = x\n") == []
    with pytest.raises(configparser.Error):
        pyreq.setup_cfg_names("not an ini file")


def test_setup_py_reads_literals_and_never_runs_code() -> None:
    src = (
        "import os\nfrom setuptools import setup\nimport setuptools\n"
        "os.system('echo never')\n"
        "setup(name='a', install_requires=['requests>=2', 7, 'flask'], setup_requires=('wheel',),\n"
        "      tests_require={'pytest'}, extras_require={'x': ['numpy'], 'y': BUILT, 'z': ['pandas']}, version='1')\n"
        "setuptools.setup(install_requires=['cryptography'], extras_require=EXTRAS, dependency_links=['x'])\n"
        "setup(install_requires=BASE + ['computed'])\nprint(setup)\n"
    )
    assert names(pyreq.setup_py_names, src) == [
        "cryptography",
        "flask",
        "numpy",
        "pandas",
        "pytest",
        "requests",
        "wheel",
    ]
    with pytest.raises(SyntaxError):
        pyreq.setup_py_names("def (")


def test_pyproject_reads_every_table_tools_use() -> None:
    text = """
[build-system]
requires = ["setuptools>=61", "wheel"]
[project]
dependencies = ["requests>=2", "Foo_Bar"]
[project.optional-dependencies]
test = ["pytest"]
[dependency-groups]
dev = ["ruff", {include-group = "test"}]
[tool.poetry.dependencies]
python = "^3.9"
django = "^4"
[tool.poetry.dev-dependencies]
black = "*"
[tool.poetry.group.docs.dependencies]
sphinx = "*"
[tool.poetry.group.bare]
optional = true
[tool.uv]
dev-dependencies = ["mypy"]
[tool.pdm.dev-dependencies]
lint = ["flake8"]
"""
    assert names(pytoml.pyproject_names, text) == sorted(
        ["setuptools", "wheel", "requests", "Foo_Bar", "pytest", "ruff", "django", "black", "sphinx", "mypy", "flake8"]
    )
    assert pytoml.pyproject_names("[tool]\nx = 1\n") == []
    assert pytoml.pyproject_names('[project]\ndependencies = "oops"\n') == []


def test_pipfile_reads_packages_and_dev_packages() -> None:
    text = '[[source]]\nname = "pypi"\n[packages]\nrequests = "*"\n[dev-packages]\npytest = {version = "*"}\n'
    assert names(pytoml.pipfile_names, text) == ["pytest", "requests"]
    assert pytoml.pipfile_names("[scripts]\nx = 'y'\n") == []


def test_package_json_reads_tables_aliases_overrides_resolutions_catalogs() -> None:
    text = """{
  "dependencies": {"a": "1", "b": "npm:real-b@^2", "c": "npm:@scope/real-c@1"},
  "devDependencies": {"d": "1"}, "optionalDependencies": {"e": "1"}, "peerDependencies": {"f": "1"},
  "bundledDependencies": ["g", 3], "bundleDependencies": "nope",
  "overrides": {"h": "1", "i@^2": {".": "1", "j": {"k": "npm:real-k@1"}}, "l": 3},
  "resolutions": {"**/m": "1", "n/@s/o": "1", "p@^1": "npm:real-p", "*": "1", "": "1", "@lone": "1"},
  "catalog": {"q": "1"}, "catalogs": {"legacy": {"r": "npm:real-r"}, "bad": 1},
  "workspaces": {"packages": ["packages/*"], "catalog": {"s": "1"}}
}"""
    assert names(node.package_json_names, text) == sorted(
        [
            "a",
            "b",
            "real-b",
            "c",
            "@scope/real-c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j",
            "k",
            "real-k",
            "l",
            "m",
            "n",
            "@s/o",
            "p",
            "real-p",
            "@lone",
            "q",
            "r",
            "real-r",
            "s",
        ]
    )
    assert node.package_json_names('{"workspaces": ["a/*"], "overrides": 1, "resolutions": [], "catalogs": 2}') == []
    assert node.package_json_names("[]") == []
    assert node.strip_range("@scope/pkg@1") == "@scope/pkg"
    assert node.strip_range("pkg") == "pkg"


def test_cargo_reads_dev_build_target_workspace_patch_and_renames() -> None:
    text = """
[dependencies]
serde = "1"
alias = { package = "real-crate", version = "1" }
local = { path = "../local" }
[dev-dependencies]
criterion = "0.5"
[build-dependencies]
cc = "1"
[dev_dependencies]
old_dev = "1"
[target.'cfg(unix)'.dependencies]
libc = "0.2"
[target.x86_64-pc-windows-msvc.build-dependencies]
winres = "0.1"
[workspace.dependencies]
tokio = "1"
[patch.crates-io]
patched = { git = "https://example.com/p" }
[replace]
"replaced:1.0.0" = { git = "https://example.com/r" }
"""
    assert names(rust.cargo_names, text) == sorted(
        ["serde", "real-crate", "criterion", "cc", "old_dev", "libc", "winres", "tokio", "patched", "replaced"]
    )
    assert rust.cargo_names('[package]\nname = "x"\n[target]\n') == []
    assert rust.cargo_names("[replace]\n") == []


def test_gemfile_and_gemspec() -> None:
    text = (
        "source 'https://rubygems.org'\n# gem 'commented'\ngem 'rails', '~> 7'\n  gem \"pg\"\ngroup :test do\n  gem('rspec')\nend\n"
        "=begin\ngem 'in-block'\n=end\ngem 'after'\nputs 'gem x'\n"
        "Gem::Specification.new do |s|\n  s.add_dependency 'thor'\n  s.add_development_dependency(\"rake\")\n  s.add_runtime_dependency 'zeitwerk'\nend\n"
    )
    assert names(ruby.gemfile_names, text) == ["after", "pg", "rails", "rake", "rspec", "thor", "zeitwerk"]


def test_composer_skips_platform_requirements() -> None:
    text = '{"require": {"php": ">=8", "ext-json": "*", "a/b": "1"}, "require-dev": {"c/d": "1", "composer-plugin-api": "*"}}'
    assert names(php.composer_names, text) == ["a/b", "c/d"]
    assert php.composer_names('{"require": []}') == []
    assert php.composer_names("[]") == []


def test_review_round_forms() -> None:
    assert pyreq.includes("-rbase.txt\n-cother.txt\n") == ["base.txt", "other.txt"]
    assert names(pyreq.requirement_names, "# c \\\nevil\nok\n") == ["evil", "ok"]
    assert names(pyreq.setup_py_names, "setup(install_requires='single>=1', tests_require='a\\nb')") == [
        "a",
        "b",
        "single",
    ]
    toml = '[tool.uv]\noverride-dependencies = ["o"]\nconstraint-dependencies = ["c"]\n[tool.hatch.envs.t]\ndependencies = ["h"]\n'
    assert names(pytoml.pyproject_names, toml) == ["c", "h", "o"]
    pkg = (
        '{"pnpm": {"overrides": {"a": "npm:real@1"}}, "dependencies": {"w": "workspace:*", "f": "file:../f", "n": "1"}}'
    )
    assert names(node.package_json_names, pkg) == ["a", "n", "real"]
    assert names(node.package_json_names, '{"pnpm": 1}') == []
    cargo = '[dependencies]\nlocal = { path = "../l" }\nboth = { path = "../b", version = "1" }\ngitty = { path = "x", git = "g" }\n'
    assert names(rust.cargo_names, cargo) == ["both", "gitty"]
    assert names(
        ruby.gemfile_names,
        "group :t do gem 'a' end\ngem 'b'; gem('c')\ns.add_runtime_dependency(%q<d>.freeze, ['1'])\n",
    ) == ["a", "b", "c", "d"]


def test_requirement_option_forms() -> None:
    assert names(pyreq.requirement_names, "-egit+https://x/a.git#egg=evil\n-e src\n-e src#egg=named\n") == [
        "evil",
        "named",
    ]
    assert pyreq.includes("-r a.txt -c b.txt\n") == ["a.txt"]
