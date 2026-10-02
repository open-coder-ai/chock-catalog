"""lockfile-integrity: poetry, uv, Pipfile, Cargo, go.sum, Gemfile, composer and NuGet lockfile readers."""

from __future__ import annotations

import json

import pytest
from policies.lockkit import SHA40, model, other, python, rules, rules_of

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
    assert got["requests"].integrity == (f"requests.whl|{SHA256}",)
    assert (got["httpx"].git, got["httpx"].pinned, got["httpx"].expect) == (True, True, False)
    assert got["private"].source == "https://pypi.corp.example/simple"
    assert got["PyYAML"].integrity == (f"PyYAML.whl|{SHA256}",)
    # a git source on a host no person allowlisted is refused like any other off-registry source
    assert rules_of("poetry.lock", text) == [model.SOURCE, model.SOURCE, model.MISSING]


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
    assert rules_of("uv.lock", text) == [model.SOURCE, model.SOURCE, model.SOURCE, model.MISSING]


def test_uv_refuses_a_source_that_is_local_and_remote_at_once() -> None:
    text = 'version = 1\n[[package]]\nname = "c"\nversion = "1"\nsource = { registry = "https://pypi.org/simple", editable = "." }\n'
    with pytest.raises(LockError, match="both local"):
        python.uv_lock(text)


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
            "docs": {"evil": {"file": "http://evil.example/e.whl", "hashes": [SHA256]}},
        }
    )
    got = {e.name: e for e in python.pipfile_lock(text)}
    assert set(got) == {"_meta.sources", "ok", "nohash", "g", "url", "evil"}  # custom categories are read too
    assert got["g"].pinned is False
    rules = rules_of("Pipfile.lock", text)
    assert rules == [model.SOURCE, model.MISSING, model.SOURCE, model.UNPINNED, model.SOURCE, model.SOURCE]


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
    rules = rules_of("Cargo.lock", text)
    assert rules == [model.SOURCE, model.MISSING, model.SOURCE, model.SOURCE, model.MISSING]


def test_a_pypi_file_keeps_its_hash_whatever_the_algorithm() -> None:
    def uv(files: str) -> list:
        return python.uv_lock(
            f'[[package]]\nname = "a"\nversion = "1"\nsource = {{ registry = "https://pypi.org/simple" }}\n{files}'
        )

    sha512 = "sha512:" + "e" * 128
    wheel = f'wheels = [{{ url = "https://files.pythonhosted.org/a.whl", hash = "{SHA256}" }}]\n'
    old = uv(f'sdist = {{ url = "https://files.pythonhosted.org/a.tar.gz", hash = "{"sha256:" + "b" * 64}" }}\n{wheel}')
    swapped = uv(f'sdist = {{ url = "https://files.pythonhosted.org/x/a.tar.gz", hash = "{sha512}" }}\n{wheel}')
    renamed = uv(f'sdist = {{ url = "https://files.pythonhosted.org/b.tar.gz", hash = "{sha512}" }}\n{wheel}')
    added = uv(
        f'sdist = {{ url = "https://files.pythonhosted.org/a.tar.gz", hash = "{"sha256:" + "b" * 64}" }}\nwheels = [{{ url = "https://files.pythonhosted.org/a.whl", hash = "{SHA256}" }}, {{ url = "https://files.pythonhosted.org/a2.whl", hash = "{sha512}" }}]\n'
    )
    assert [f.rule for f in rules.delta_findings("uv.lock", swapped, old)] == [model.CHANGED]
    assert [f.rule for f in rules.delta_findings("uv.lock", renamed, old)] == [model.CHANGED]
    assert rules.delta_findings("uv.lock", added, old) == []
    assert rules.delta_findings("uv.lock", old[:1] and uv(wheel), old) == []  # a file only dropped
