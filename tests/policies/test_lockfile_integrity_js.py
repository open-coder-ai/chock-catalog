"""lockfile-integrity: npm, bun, yarn (classic and Berry) and pnpm lockfile readers."""

from __future__ import annotations

import json

import pytest
from policies.lockkit import SHA40, h, model, npm, npm_lock, pkg, pnpm, rules_of

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
    # every alias is held for a person (npm ci checks no declaration); d's URL is another package's
    assert rules_of("package-lock.json", text) == [model.NPM_ALIAS, model.NPM_ALIAS, model.SOURCE]
    orphan = json.dumps({"packages": {"x/node_modules/y": {**pkg("z", "1.0.0"), "name": "z"}, "x": 1}})
    with pytest.raises(model.LockError):
        npm.package_lock(orphan)


def test_npm_hoists_an_alias_a_dependency_declares() -> None:
    url = "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"
    packages = {
        "": {"dependencies": {"glob": "^10.0.0"}},
        "node_modules/@isaacs/cliui": {
            **pkg("@isaacs/cliui", "8.0.2"),
            "dependencies": {"string-width-cjs": "npm:string-width@^4.2.0"},
        },
        "node_modules/string-width-cjs": {**pkg("string-width", "4.2.3", resolved=url), "name": "string-width"},
    }
    text = json.dumps({"lockfileVersion": 3, "packages": packages})
    assert [e.name for e in npm.package_lock(text)][-1] == "string-width"
    assert rules_of("package-lock.json", text) == [model.NPM_ALIAS]  # asked, not refused
    rooted = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {**packages, "": {"dependencies": {"string-width-cjs": "npm:string-width@^4.2.0"}}},
        }
    )
    assert rules_of("package-lock.json", rooted) == [model.NPM_ALIAS]  # the root entry is lock text too


def test_a_forged_alias_on_another_entry_does_not_pass_silently() -> None:
    evil = "https://registry.npmjs.org/evil-pad/-/evil-pad-1.3.1.tgz"
    lock = npm_lock(
        {
            "glob": {**pkg("glob", "10.4.5"), "dependencies": {"left-pad": "npm:evil-pad@^1.3.1"}},
            "left-pad": {**pkg("evil-pad", "1.3.1", resolved=evil), "name": "evil-pad"},
        }
    )
    assert rules_of("package-lock.json", lock) == [model.NPM_ALIAS]
    for declarer in ("", "packages/fake"):  # the lock's own root entry, a workspace nothing lists
        forged = json.loads(lock)
        forged["packages"].setdefault(declarer, {})["dependencies"] = {"left-pad": "npm:evil-pad@^1.3.1"}
        del forged["packages"]["node_modules/glob"]["dependencies"]
        assert rules_of("package-lock.json", json.dumps(forged)) == [model.NPM_ALIAS]
