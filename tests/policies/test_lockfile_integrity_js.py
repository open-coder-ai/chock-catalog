"""lockfile-integrity: npm, bun, yarn (classic and Berry) and pnpm lockfile readers."""

from __future__ import annotations

import json

import pytest
from policies.lockkit import SHA40, h, model, npm, npm_lock, pkg, pnpm, rules_of, yarn

LockError = model.LockError


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("{", "not valid JSON"),
        ("[]", "not a JSON object"),
        ('{"packages": []}', "'packages' is not an object"),
        ('{"packages": {"node_modules/a": 1}}', "is not an object"),
        ('{"packages": {"node_modules/a": {"resolved": 5}}}', "'resolved' is not a string"),
        ('{"dependencies": [1]}', "'dependencies' is not an object"),
        ('{"dependencies": {"a": 1}}', "is not an object"),
    ],
)
def test_package_lock_refuses_what_it_cannot_read(text: str, why: str) -> None:
    with pytest.raises(LockError, match=why):
        npm.package_lock(text)


def test_package_lock_v2_reads_packages_and_skips_links_and_bundles() -> None:
    text = npm_lock(
        {
            "left-pad": pkg("left-pad", "1.3.0"),
            "left-pad/node_modules/deep": pkg("deep", "2.0.0", hasInstallScript=True),
            "linked": {"resolved": "packages/linked", "link": True},
            "bundled": {**pkg("bundled", "1.0.0"), "inBundle": True},
            "left-pad/node_modules/inner": {"version": "1.0.0", "inBundle": True},
            "alias": {**pkg("real", "1.0.0"), "name": "real"},
        }
    )
    got = {e.ident: e for e in npm.package_lock(text)}
    # a root-level bundle is still fetched by npm; only one shipped inside a dependency's tarball is skipped
    # a `name` field the parent never declared as an npm: alias does not rename the folder's package
    assert set(got) == {"left-pad@1.3.0", "deep@2.0.0", "alias@1.0.0", "bundled@1.0.0"}
    assert got["left-pad@1.3.0"].transitive is False
    assert got["deep@2.0.0"].transitive is True
    assert got["deep@2.0.0"].install is True
    assert got["left-pad@1.3.0"].line > 1


def test_package_lock_v1_reads_nested_dependencies() -> None:
    text = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a.tgz", "integrity": h(),
                      "dependencies": {"b": {"version": "2.0.0", "integrity": h("B")}}},
                "g": {"version": f"git+ssh://git@github.com/x/g.git#{SHA40}"},
                "bun": {"version": "1.0.0", "bundled": True},
                "dir": {"version": "file:../dir"},
                "tar": {"version": "file:vendor/tar-1.0.0.tgz"},
            },
        }
    )  # fmt: skip
    got = {e.name: e for e in npm.package_lock(text)}
    assert set(got) == {"a", "b", "g", "tar"}
    assert (got["a"].transitive, got["b"].transitive) == (False, True)
    assert got["g"].source.startswith("git+ssh") and got["g"].expect is False
    assert got["tar"].source == "file:vendor/tar-1.0.0.tgz"
    assert npm.package_lock("{}") == []


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("{", "not valid JSONC"),
        ('{"packages": {}, "packages": {}}', "a key given twice"),
        ("[]", "no 'packages' object"),
        ('{"packages": {"a": []}}', "is not a"),
        ('{"packages": {"a": [1]}}', "is not a"),
    ],
)
def test_bun_lock_refuses_what_it_cannot_read(text: str, why: str) -> None:
    with pytest.raises(LockError, match=why):
        npm.bun_lock(text)


def test_bun_lock_reads_registry_protocol_and_local_entries() -> None:
    text = """{
  // bun writes trailing commas
  "lockfileVersion": 1,
  "packages": {
    "a": ["a@1.0.0", "", {}, "%s"],
    "b": ["b@1.0.0", "https://npm.internal.example/", {}, "%s"],
    "c": ["c@github:x/c#abc", {}, "x-c-abc"],
    "d": ["d@npm:real@1.0.0", "", {}, "%s"],
    "w": ["w@workspace:packages/w"],
    "e": ["e@1.0.0"],
  },
}""" % (h(), h(), h())
    got = {e.name: e for e in npm.bun_lock(text)}
    assert set(got) == {"a", "b", "c", "d", "e"}
    assert got["a"].source is None and got["a"].integrity
    assert got["b"].source == "https://npm.internal.example/"
    assert got["c"].source == "github:x/c#abc" and got["c"].expect is False
    assert got["d"].source is None
    assert got["e"].integrity == () and got["e"].expect is True


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
    assert rules_of("yarn.lock", classic) == []
    v1 = json.dumps({"dependencies": {"alias": {"version": "npm:real@1.0.0", "resolved": url, "integrity": h()}}})
    assert rules_of("package-lock.json", v1) == []


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


PNPM = f"""lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0

packages:
  a@1.0.0:
    resolution: {{integrity: {h()}}}
    requiresBuild: true
  '@s/b@2.0.0(react@18.0.0)':
    resolution: {{integrity: sha1-{"B" * 27}=}}
    requiresBuild: true
  c@https://codeload.github.com/x/c/tar.gz/{SHA40}:
    resolution: {{tarball: https://codeload.github.com/x/c/tar.gz/{SHA40}}}
    version: 1.0.0
  g@git+https://github.com/x/g.git#main:
    resolution: {{type: git, repo: https://github.com/x/g.git, commit: main}}
  d@1.0.0:
    resolution: {{directory: packages/d, type: directory}}
  l@link:../l:
    resolution: {{}}
  f@file:vendor/f.tgz:
    resolution: {{integrity: {h()}}}
  m@1.0.0:
    engines: {{node: '>=8'}}
"""


def test_pnpm_lock_reads_packages_and_importers() -> None:
    got = {e.name: e for e in pnpm.pnpm_lock(PNPM)}
    assert set(got) == {"a", "@s/b", "c", "g", "f", "m"}
    assert (got["a"].transitive, got["a"].install) == (False, True)
    assert (got["@s/b"].version, got["@s/b"].weak, got["@s/b"].transitive) == ("2.0.0", True, True)
    assert got["c"].version == "1.0.0" and got["c"].source.startswith("https://codeload")
    assert got["g"].pinned is False and got["g"].expect is False
    assert got["f"].source == "file:vendor/f.tgz"
    assert got["m"].expect is True and got["m"].integrity == ()


def test_pnpm_lock_v5_keys_and_root_dependencies() -> None:
    text = f"lockfileVersion: 5.4\n\ndependencies:\n  a: 1.0.0\n\npackages:\n  /a/1.0.0_react@17.0.0:\n    resolution: {{integrity: {h()}}}\n  /@s/b/2.0.0:\n    resolution: {{integrity: {h()}}}\n"
    got = {e.name: e for e in pnpm.pnpm_lock(text)}
    assert (got["a"].version, got["a"].transitive) == ("1.0.0", False)
    assert got["@s/b"].version == "2.0.0"


@pytest.mark.parametrize(
    ("text", "why"),
    [("packages:\n\ta: 1\n", "not readable YAML"), ("packages:\n  a@1: &x\n    b: 1\n  c@1: *x\n", "an alias")],
)
def test_pnpm_lock_refuses_what_it_cannot_read(text: str, why: str) -> None:
    with pytest.raises(LockError, match=why):
        pnpm.pnpm_lock(text)


def test_an_npm_name_field_counts_only_for_a_declared_alias() -> None:
    evil = "https://registry.npmjs.org/evil-pad/-/evil-pad-1.3.1.tgz"
    forged = npm_lock({"left-pad": {**pkg("left-pad", "1.3.1", resolved=evil), "name": "evil-pad"}})
    assert rules_of("package-lock.json", forged) == [model.SOURCE]
    packages = {
        "": {"dependencies": {"left-pad": "npm:real-pad@^1.0.0"}},
        "node_modules/left-pad": {**pkg("real-pad", "1.0.0"), "name": "real-pad"},
        "node_modules/a": {**pkg("a", "1.0.0"), "dependencies": {"b": "npm:real-b@^1"}},
        "node_modules/a/node_modules/b": {**pkg("real-b", "1.0.0"), "name": "real-b"},
        "node_modules/c": {**pkg("c", "1.0.0"), "name": "c"},
        "node_modules/d": {**pkg("real-d", "1.0.0"), "name": "real-d"},
        "node_modules/e": {**pkg("e", "1.0.0"), "name": 5},
    }
    text = json.dumps({"lockfileVersion": 3, "packages": packages})
    got = [e.name for e in npm.package_lock(text)]
    assert got == ["real-pad", "a", "real-b", "c", "d", "e"]
    assert rules_of("package-lock.json", text) == [model.SOURCE]  # d's URL is another package's
    orphan = json.dumps({"packages": {"x/node_modules/y": {**pkg("z", "1.0.0"), "name": "z"}, "x": 1}})
    with pytest.raises(model.LockError):
        npm.package_lock(orphan)


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
