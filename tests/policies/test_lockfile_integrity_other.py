"""lockfile-integrity: go.sum, Gemfile.lock, composer.lock and NuGet packages.lock.json readers."""

from __future__ import annotations

import json

import pytest
from policies.lockkit import SHA40, model, other, rules_of

LockError = model.LockError


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
    assert rules_of("Gemfile.lock", GEMFILE_LOCK) == [model.SOURCE, model.SOURCE, model.UNPINNED, model.SOURCE]
    with pytest.raises(LockError, match="before any 'remote:'"):
        other.gemfile_lock("GEM\n  specs:\n    rake (1.0)\n")


@pytest.mark.parametrize(("text", "why"), [("", "no GEM, GIT or PATH"), ("vendor/real.lock\n", "unknown section")])
def test_gemfile_lock_refuses_what_is_not_a_bundler_lock(text: str, why: str) -> None:
    with pytest.raises(LockError, match=why):
        other.gemfile_lock(text)


def test_gemfile_lock_reads_plugin_sources_as_git() -> None:
    text = "PLUGIN SOURCE\n  remote: http://evil.example/p.git\n  revision: main\n  specs:\n    p (1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n"
    assert rules_of("Gemfile.lock", text) == [model.SOURCE, model.UNPINNED]


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
