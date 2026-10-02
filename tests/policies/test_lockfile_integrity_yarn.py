"""lockfile-integrity: yarn.lock readers, classic and Berry."""

from __future__ import annotations

import json

import pytest
from policies.lockkit import SHA40, h, model, rules_of, yarn

LockError = model.LockError


CLASSIC = f"""# yarn lockfile v1


"@s/a@^1.0.0", "@s/a@^1.1.0":
  version "1.1.0"
  resolved "https://registry.yarnpkg.com/@s/a/-/a-1.1.0.tgz#{"c" * 40}"
  integrity {h()}
  dependencies:
    b "^2.0.0"

b@^2.0.0:
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/b/-/b-2.0.0.tgz#{"d" * 40}"

g@git+ssh://git@github.com/x/g.git:
  version "1.0.0"
  resolved "git+ssh://git@github.com/x/g.git#{"e" * 40}"

local@file:../local:
  version "0.0.0"

tar@file:vendor/tar.tgz:
  version "1.0.0"
"""


def test_classic_yarn_lock_reads_entries() -> None:
    got = {e.name: e for e in yarn.yarn_lock(CLASSIC)}
    assert set(got) == {"@s/a", "b", "g", "tar"}
    assert got["@s/a"].integrity == (h(),) and got["@s/a"].weak is False
    assert got["b"].weak is True and got["b"].integrity == ("sha1hex-" + "d" * 40,)
    assert got["g"].weak is False and got["g"].integrity == ()
    assert got["tar"].source is None and got["tar"].expect is True
    assert rules_of("yarn.lock", CLASSIC) == [model.WEAK, model.SOURCE, model.MISSING]


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("\ta@1:\n", "not a yarn.lock entry"),
        ("a@1\n", "not a yarn.lock entry"),
        ("  version 1\n", "indented where"),
        ("a@1:\n   version 1\n", "indented where"),
        ("a@1:\n    x y\n", "indented where"),
        ('a@1:\n  version "1\n', "does not close"),
        ("a@1:\n  version 1\n  version 2\n", "repeats the field"),
    ],
)
def test_classic_yarn_lock_refuses_other_shapes(text: str, why: str) -> None:
    with pytest.raises(LockError, match=why):
        yarn.yarn_lock(text)


BERRY = f"""__metadata:
  version: 8
  cacheKey: 10c0

"a@npm:^1.0.0":
  version: 1.0.0
  resolution: "a@npm:1.0.0"
  checksum: 10c0/{"f" * 64}
  linkType: hard

"b@npm:^1.0.0":
  version: 1.0.0
  resolution: "b@npm:1.0.0"
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"g@git+ssh://git@github.com/x/g.git":
  version: 1.0.0
  resolution: "g@git+ssh://git@github.com/x/g.git#commit=main"

"p@patch:p@npm%3A1.0.0#./p.patch":
  version: 1.0.0
  resolution: "p@patch:p@npm%3A1.0.0#./p.patch::version=1.0.0"

"x@npm:^1.0.0":
  version: 1.0.0
  resolution: "x@npm:1.0.0::__archiveUrl=https%3A%2F%2Fevil.example%2Fx.tgz&other=1"
  checksum: 10c0/{"e" * 64}
"""


def test_berry_yarn_lock_reads_resolutions() -> None:
    got = {e.name: e for e in yarn.yarn_lock(BERRY)}
    assert set(got) == {"a", "b", "g", "p", "x"}
    assert got["a"].integrity and got["a"].source is None
    assert got["b"].expect is True and got["b"].integrity == ()
    assert got["g"].pinned is False
    assert got["p"].source is None and got["p"].expect is True  # a patch of a registry package
    assert got["x"].source == "https://evil.example/x.tgz"
    assert got["a"].integrity == ("berry10c0/" + "f" * 64,)
    assert sorted(rules_of("yarn.lock", BERRY)) == sorted(
        [model.MISSING, model.MISSING, model.SOURCE, model.UNPINNED, model.SOURCE]
    )


@pytest.mark.parametrize(
    ("resolution", "source"),
    [
        ("left-pad@patch:left-pad@https%3A%2F%2Fevil.example%2Fx.tgz#./p.patch::version=1.3.0&hash=abc", "https://evil.example/x.tgz"),
        ("left-pad@npm:1.3.0::__archive%55rl=https%3A%2F%2Fevil.example%2Fx.tgz", "https://evil.example/x.tgz"),
        ("left-pad@patch:left-pad@workspace%3Apackages%2Fl#./p.patch", None),
        ("left-pad@patch:left-pad@npm%3A1.3.0#./p.patch::version=1.3.0", None),
    ],
)  # fmt: skip
def test_berry_judges_the_reference_a_patch_wraps_and_decoded_parameters(resolution: str, source: str | None) -> None:
    text = f'__metadata:\n  version: 8\n  cacheKey: 8\n\n"e":\n  version: 1.3.0\n  resolution: "{resolution}"\n  checksum: {"a" * 64}\n'
    got = yarn.yarn_lock(text)
    assert [e.source for e in got] == ([source] if "workspace" not in resolution else [])
    if got:
        assert got[0].integrity == ("berry8/" + "a" * 64,)


def test_classic_yarn_reads_a_field_written_with_a_colon() -> None:
    text = 'left-pad@^1.3.0:\n  version "1.3.0"\n  resolved: "https://evil.example/left-pad-1.3.0.tgz"\n'
    assert [e.source for e in yarn.yarn_lock(text)] == ["https://evil.example/left-pad-1.3.0.tgz"]


def test_an_npm_alias_is_judged_by_the_package_it_installs() -> None:
    url = "https://registry.npmjs.org/real/-/real-1.0.0.tgz"
    classic = f'alias@npm:real@^1.0.0:\n  version "1.0.0"\n  resolved "{url}"\n  integrity {h()}\n'
    assert rules_of("yarn.lock", classic) == [model.NPM_ALIAS]  # judged as real, and asked about
    v1 = json.dumps({"dependencies": {"alias": {"version": "npm:real@1.0.0", "resolved": url, "integrity": h()}}})
    assert rules_of("package-lock.json", v1) == [model.NPM_ALIAS]


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("__metadata:\n  version: 8\n\tbad: [\n", "not readable YAML"),
        ("__metadata:\n  version: 8\na: &x\n  resolution: y\nb: *x\n", "an alias"),
        ('__metadata:\n  version: 8\n"a@npm:1":\n  version: 1\n', "has no resolution"),
    ],
)
def test_berry_yarn_lock_refuses_what_it_cannot_read(text: str, why: str) -> None:
    with pytest.raises(LockError, match=why):
        yarn.yarn_lock(text)


@pytest.mark.parametrize(
    ("resolution", "pinned", "git"),
    [
        (f"a@https://github.com/x/a.git#commit={SHA40}", True, True),
        ("a@https://github.com/x/a.git#head=main", False, True),
        (f"a@https://github.com/x/a#commit={SHA40}x", False, True),
        ("a@https://github.com/x/a#tag=v1", False, True),
        ("a@git+ssh://git@github.com/x/a.git#commit=main", False, False),
        ("a@https://cdn.example/a.tgz", True, False),
    ],
)
def test_berry_reads_git_references_and_their_pins(resolution: str, pinned: bool, git: bool) -> None:
    text = f'__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"a":\n  version: 1.0.0\n  resolution: "{resolution}"\n'
    (entry,) = yarn.yarn_lock(text)
    assert (entry.pinned, entry.git) == (pinned, git)


def test_berry_refuses_a_checksum_under_another_cache_key() -> None:
    text = f'__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"a@npm:1":\n  version: 1.0.0\n  resolution: "a@npm:1.0.0"\n  checksum: 9/{"c" * 64}\n'
    with pytest.raises(model.LockError, match="cache key"):
        yarn.yarn_lock(text)


@pytest.mark.parametrize(
    ("resolution", "pinned"),
    [
        (f"a@https://github.com/x/a.git#head=main&x=#commit={SHA40}", False),
        ("a@https://github.com/x/a#main", False),
        ("a@https://github.com/x/a", False),
        (f"a@https://github.com/x/a#{SHA40}", True),
        (f"a@https://github.com/x/a.git#commit={SHA40}&tag=v1", False),
        (f"a@https://github.com/x/a.git#commit={SHA40}&commit={SHA40}", False),
        (f"a@https://github.com/x/a.git#commi%74={SHA40}", True),
        ("a@https://github.com/x/a/tarball/v1", True),
    ],
)
def test_berry_reads_selectors_as_a_query_string(resolution: str, pinned: bool) -> None:
    text = f'__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"a":\n  version: 1.0.0\n  resolution: "{resolution}"\n'
    (entry,) = yarn.yarn_lock(text)
    assert entry.pinned is pinned


def test_berry_flags_a_descriptor_resolved_to_another_package() -> None:
    entry = (
        '"left-pad@npm:^1.3.0, left-pad@npm:^1.3.1":\n  version: 1.3.1\n  resolution: "{}@npm:1.3.1"\n  checksum: 10c0/'
        + "c" * 64
        + "\n"
    )
    head = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
    assert [e.alias for e in yarn.yarn_lock(head + entry.format("evil-pad"))] == [True]
    assert [e.alias for e in yarn.yarn_lock(head + entry.format("left-pad"))] == [False]


def test_every_name_in_a_header_must_be_the_package_installed() -> None:
    url = "https://registry.yarnpkg.com/evil-pad/-/evil-pad-1.3.1.tgz"
    classic = f'evil-pad@^1.3.1, left-pad@^1.3.1:\n  version "1.3.1"\n  resolved "{url}"\n  integrity {h()}\n'
    assert rules_of("yarn.lock", classic) == [model.NPM_ALIAS]
    bare = classic.replace(", ", ",", 1)  # yarn's tokenizer ends an unquoted spec at the comma alone
    assert rules_of("yarn.lock", bare) == [model.NPM_ALIAS]
    quoted = classic.replace("evil-pad@^1.3.1, left-pad@^1.3.1", '"evil-pad@^1.3.1","left-pad@^1.3.1"')
    assert rules_of("yarn.lock", quoted) == [model.NPM_ALIAS]
    plain = f'evil-pad@^1.3.0, evil-pad@^1.3.1:\n  version "1.3.1"\n  resolved "{url}"\n  integrity {h()}\n'
    assert rules_of("yarn.lock", plain) == []
    berry = (
        '__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"evil-pad@npm:^1.3.1, left-pad@npm:^1.3.1":\n'
        f'  version: 1.3.1\n  resolution: "evil-pad@npm:1.3.1"\n  checksum: 10c0/{"c" * 64}\n'
    )
    assert [e.alias for e in yarn.yarn_lock(berry)] == [True]
