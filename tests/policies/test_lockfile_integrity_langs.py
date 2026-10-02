"""lockfile-integrity: poetry, uv, Pipfile, Cargo, go.sum, Gemfile, composer and NuGet lockfile readers."""

from __future__ import annotations

import json

import pytest
from policies.lockkit import SHA40, model, other, python, rules_of

LockError = model.LockError
SHA256 = "sha256:" + "a" * 64


def test_poetry_lock_reads_registry_git_and_legacy_hashes() -> None:
    text = f"""[[package]]
name = "requests"
version = "2.32.0"
files = [{{file = "requests.whl", hash = "{SHA256}"}}]

[[package]]
name = "httpx"
version = "0.27.0"

[package.source]
type = "git"
url = "https://github.com/encode/httpx.git"
resolved_reference = "{SHA40}"

[[package]]
name = "private"
version = "1.0.0"
files = []

[package.source]
type = "legacy"
url = "https://pypi.corp.example/simple"

[[package]]
name = "local"
version = "0.1.0"

[package.source]
type = "directory"
url = "../local"

[[package]]
name = "PyYAML"
version = "6.0"

[metadata]
lock-version = "1.1"

[metadata.files]
pyyaml = [{{file = "PyYAML.whl", hash = "{SHA256}"}}]
"""
    got = {e.name: e for e in python.poetry_lock(text)}
    assert set(got) == {"requests", "httpx", "private", "PyYAML"}
    assert got["requests"].integrity == (SHA256,)
    assert (got["httpx"].git, got["httpx"].pinned, got["httpx"].expect) == (True, True, False)
    assert got["private"].source == "https://pypi.corp.example/simple"
    assert got["PyYAML"].integrity == (SHA256,)
    assert rules_of("poetry.lock", text) == [model.SOURCE, model.MISSING]


def test_poetry_lock_tolerates_odd_metadata() -> None:
    assert python.poetry_lock('metadata = 1\n[[package]]\nname = "a"\nversion = "1"\nfiles = 3\n')[0].integrity == ()
    assert python.poetry_lock("[metadata]\nfiles = 1\n") == []


@pytest.mark.parametrize("text", ["[[package]\n", "package = 1\n", "package = [1]\n"])
def test_toml_locks_refuse_what_they_cannot_read(text: str) -> None:
    with pytest.raises(LockError):
        python.uv_lock(text)


def test_uv_lock_reads_registry_git_url_and_local_sources() -> None:
    text = f"""version = 1

[[package]]
name = "app"
version = "0.1.0"
source = {{ editable = "." }}

[[package]]
name = "idna"
version = "3.7"
source = {{ registry = "https://pypi.org/simple" }}
sdist = {{ url = "https://files.pythonhosted.org/idna-3.7.tar.gz", hash = "{SHA256}" }}
wheels = [{{ url = "https://cdn.evil.example/idna-3.7.whl", hash = "{SHA256}" }}]

[[package]]
name = "g"
version = "1.0"
source = {{ git = "https://github.com/x/g?rev=main#{SHA40}" }}

[[package]]
name = "nosrc"
version = "1.0"
"""
    got = [(e.name, e.source, e.git, e.pinned) for e in python.uv_lock(text)]
    assert ("idna", "https://pypi.org/simple", False, True) in got
    assert ("g", f"https://github.com/x/g?rev=main#{SHA40}", True, True) in got
    assert ("nosrc", "", False, True) in got
    assert rules_of("uv.lock", text) == [model.SOURCE, model.SOURCE, model.MISSING]


def test_pipfile_lock_reads_sources_and_packages() -> None:
    text = json.dumps(
        {
            "_meta": {"sources": [{"name": "corp", "url": "http://pypi.corp.example/simple"}, "x"]},
            "default": {
                "ok": {"version": "==1.0", "hashes": [SHA256]},
                "nohash": {"version": "==1.0", "hashes": "x"},
                "g": {"git": "https://github.com/x/g.git", "ref": "main"},
                "loc": {"path": "."},
                "ed": {"editable": True, "path": "."},
                "url": {"file": "https://cdn.example/u.whl", "hashes": [SHA256]},
            },
            "develop": {},
        }
    )
    got = {e.name: e for e in python.pipfile_lock(text)}
    assert set(got) == {"_meta.sources", "ok", "nohash", "g", "url"}
    assert got["g"].pinned is False
    assert rules_of("Pipfile.lock", text) == [model.SOURCE, model.MISSING, model.UNPINNED, model.SOURCE]


@pytest.mark.parametrize(
    ("text", "why"),
    [("{", "not valid JSON"), ("[]", "not a JSON object"), ('{"default": []}', "is not an object"),
     ('{"default": {"a": 1}}', "is not an object")],
)  # fmt: skip
def test_pipfile_lock_refuses_what_it_cannot_read(text: str, why: str) -> None:
    with pytest.raises(LockError, match=why):
        python.pipfile_lock(text)


def test_cargo_lock_reads_registry_git_and_path_crates() -> None:
    text = f"""version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{"b" * 64}"

[[package]]
name = "alt"
version = "1.0.0"
source = "sparse+https://crates.corp.example/index/"

[[package]]
name = "g"
version = "1.0.0"
source = "git+https://github.com/x/g?branch=main#{SHA40}"

[[package]]
name = "odd"
version = "1.0.0"
source = "path+file:///x"

[[package]]
name = "old"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
"checksum old 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)" = "{"c" * 64}"
"""
    got = {e.name: e for e in other.cargo_lock(text)}
    assert set(got) == {"serde", "alt", "g", "odd", "old"}
    assert got["serde"].source is None and got["serde"].integrity
    assert got["alt"].source == "https://crates.corp.example/index/"
    assert (got["g"].git, got["g"].pinned) == (True, True)
    assert got["old"].integrity == ("c" * 64,)
    assert rules_of("Cargo.lock", text) == [model.SOURCE, model.MISSING, model.SOURCE, model.MISSING]


def test_go_sum_reads_lines_and_refuses_others() -> None:
    line = "golang.org/x/text v0.14.0 h1:" + "A" * 43 + "="
    got = other.go_sum(f"{line}\r\n\n{line.replace('v0.14.0', 'v0.14.0/go.mod')}\n")
    assert [e.ident for e in got] == ["golang.org/x/text@v0.14.0", "golang.org/x/text@v0.14.0/go.mod"]
    with pytest.raises(LockError, match="line 1"):
        other.go_sum("golang.org/x/text v0.14.0 sha256:x\n")


GEMFILE_LOCK = f"""GIT
  remote: https://github.com/rails/rails.git
  revision: {SHA40}
  specs:
    rails (8.0.0)

GIT
  remote: https://github.com/x/y.git
  branch: main
  specs:
    y (1.0.0)

PATH
  remote: .
  specs:
    app (0.1.0)

GEM
  remote: http://gems.corp.example/
  specs:
    rake (13.2.1)
      dep (>= 1)

PLATFORMS
  ruby

CHECKSUMS
  rake (13.2.1) sha256={"d" * 64}
  rails (8.0.0)

BUNDLED WITH
   2.5.0
"""


def test_gemfile_lock_reads_git_and_gem_sections_and_checksums() -> None:
    got = {e.ident: e for e in other.gemfile_lock(GEMFILE_LOCK)}
    assert set(got) == {"rails@8.0.0", "y@1.0.0", "GEM remote@http://gems.corp.example/", "rake@13.2.1"}
    assert got["rails@8.0.0"].pinned is True and got["y@1.0.0"].pinned is False
    assert got["rake@13.2.1"].integrity == ("sha256:" + "d" * 64,)
    assert got["rails@8.0.0"].integrity == ()
    assert rules_of("Gemfile.lock", GEMFILE_LOCK) == [model.UNPINNED, model.SOURCE]
    with pytest.raises(LockError, match="before any 'remote:'"):
        other.gemfile_lock("GEM\n  specs:\n    rake (1.0)\n")


def test_composer_lock_reads_dist_and_source() -> None:
    text = json.dumps(
        {
            "packages": [
                {"name": "a/a", "version": "1.0", "dist": {"type": "zip", "url": "https://api.github.com/repos/a/a/zipball/x", "shasum": "s"}},
                {"name": "b/b", "version": "1.0", "source": {"type": "git", "url": "https://github.com/b/b.git", "reference": "main"}},
                {"name": "c/c", "version": "1.0", "dist": {"type": "path", "url": "../c"}},
                {"name": "d/d", "version": "1.0", "source": {"type": "path", "url": "../d"}},
                {"name": "e/e", "version": "1.0"},
            ],
        }
    )  # fmt: skip
    got = {e.name: e for e in other.composer_lock(text)}
    assert set(got) == {"a/a", "b/b"}
    assert got["a/a"].integrity == ("s",) and got["b/b"].pinned is False
    with pytest.raises(LockError, match="'packages' is not an array"):
        other.composer_lock('{"packages": {}}')
    with pytest.raises(LockError, match="not a JSON object"):
        other.composer_lock("[]")
    with pytest.raises(LockError, match="not valid JSON"):
        other.composer_lock("{")


def test_nuget_lock_reads_packages_and_skips_projects() -> None:
    text = json.dumps(
        {"version": 1, "dependencies": {"net8.0": {
            "A": {"type": "Direct", "resolved": "1.0.0", "contentHash": "h1"},
            "B": {"type": "Transitive", "resolved": "2.0.0"},
            "P": {"type": "Project"},
        }}}
    )  # fmt: skip
    got = {e.name: e for e in other.nuget_lock(text)}
    assert set(got) == {"A", "B"}
    assert rules_of("packages.lock.json", text) == [model.MISSING]
    with pytest.raises(LockError, match="target frameworks"):
        other.nuget_lock('{"dependencies": []}')
    with pytest.raises(LockError, match="is not an object"):
        other.nuget_lock('{"dependencies": {"net8.0": {"A": 1}}}')
