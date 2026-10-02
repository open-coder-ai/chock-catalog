"""lockfile-integrity: the shared model, the host judgement and the per-file rules."""

from __future__ import annotations

import pytest
from policies.lockkit import h, model, rules, sources

E = model.Entry


@pytest.mark.parametrize(
    ("value", "hashes", "weak"),
    [
        (None, (), False),
        (42, (), False),
        ("not-a-hash", (), False),
        (h("A"), (h("A"),), False),
        ("sha1-" + "B" * 27 + "=", ("sha1-" + "B" * 27 + "=",), True),
        (f"{h('A')} sha1-{'B' * 27}=", (h("A"), "sha1-" + "B" * 27 + "="), False),
        (f"{h('A')}?opt", (h("A"),), False),
    ],
)
def test_sri_reads_npm_integrity_strings(value: object, hashes: tuple, weak: bool) -> None:
    got, is_weak = model.sri(value)
    assert (set(got), is_weak) == (set(hashes), weak)


def test_prefixed_reads_algo_hex_hashes() -> None:
    assert model.prefixed(["sha256:" + "a" * 64, None, "x"]) == (("sha256:" + "a" * 64,), False)
    assert model.prefixed(["md5:" + "a" * 32]) == (("md5:" + "a" * 32,), True)
    assert model.prefixed([]) == ((), False)


def test_lines_finds_needles_forward_then_falls_back() -> None:
    lines = model.Lines("a\nb\nc\nb\n")
    assert lines("b") == 2
    assert lines("c") == 3
    assert lines("a") == 1  # behind the cursor: its first copy
    assert lines("zz") == 1
    assert lines("b") == 4


def test_split_spec_keeps_a_scope() -> None:
    assert model.split_spec("@s/p@^1") == ("@s/p", "^1")
    assert model.split_spec("plain") == ("plain", "")


def test_a_finding_document_marks_new_only_when_asked() -> None:
    f = model.Finding(model.WEAK, "k", "p", 3, "m")
    assert f.tier == model.ASK
    assert "new" not in f.document(new=False)
    assert f.document(new=True)["new"] is True


def test_the_allowlist_loads_or_says_why_not() -> None:
    assert sources.load_allowlist(None) == ((), "")
    entries, note = sources.load_allowlist("# mirror\nnpm.internal.example\n")
    assert len(entries) == 1
    assert note == ""
    entries, note = sources.load_allowlist("bad host name\n")
    assert entries == ()
    assert "could not be read" in note


ALLOW = sources.load_allowlist("npm.internal.example\n*.corp.example\n")[0]


@pytest.mark.parametrize(
    ("source", "git", "why"),
    [
        ("https://registry.npmjs.org/x.tgz", False, ""),
        ("https://REGISTRY.NPMJS.ORG./x.tgz", False, ""),
        ("https://npm.internal.example/x.tgz", False, ""),
        ("https://a.corp.example/x.tgz", False, ""),
        ("https://corp.example/x.tgz", False, "fetched from corp.example"),
        ("https://registry.npmjs.org.evil.example/x.tgz", False, "fetched from registry.npmjs.org.evil.example"),
        ("http://registry.npmjs.org/x.tgz", False, "fetched with http:"),
        ("git+ssh://git@github.com/x/y.git", False, "fetched with git+ssh:"),
        ("git@github.com:x/y.git", False, "not a URL"),
        ("https://registry.npmjs.org@evil.example/x", False, "credentials"),
        ("https://registry.npmjs.org:8443/x", False, "port 8443"),
        ("https://registry.npmjs.org\\@evil.example/x", False, "parsers read differently"),
        ("https://github.com/x/y.git", True, "a git repository on github.com"),
        ("git+https://a.corp.example/x/y.git", True, ""),
        ("https://registry.npmjs.org/x.git", True, "a git repository on registry.npmjs.org"),
        ("git+ssh://github.com/x/y.git", True, "fetched with git+ssh:"),
        ("https://tok@github.com/x/y.git", True, "credentials"),
    ],
)
def test_a_source_is_judged_by_transport_and_host(source: str, git: bool, why: str) -> None:
    got = sources.problem(source, "npm", ALLOW, git=git)
    assert (why in got) if why else got == ""


def test_host_of_and_scheme_of_never_raise() -> None:
    assert sources.host_of("https://A.example/x") == "a.example"
    assert sources.host_of("https://a\\@b/x") == ""
    assert sources.scheme_of("GitHub:x/y") == "github"
    assert sources.scheme_of("../x") == ""


def test_rules_read_only_known_lockfiles_and_refuse_unreadable_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    assert rules.reader("a/b.txt") is None
    assert rules.reader("sub/Package-Lock.JSON") is not None
    entries, refusal = rules.read("package-lock.json", "{")
    assert entries is None
    assert refusal.rule == model.UNPARSEABLE

    def deep(_text: str) -> list:
        raise RecursionError

    monkeypatch.setitem(rules.READERS, "go.sum", deep)
    _, refusal = rules.read("go.sum", "x")
    assert "nested too deeply" in refusal.message


def test_state_findings_cover_each_per_entry_rule() -> None:
    entries = [
        E("a", "1", 1, "https://evil.example/a.tgz", "npm", (h(),), expect=True),
        E("b", "1", 2, None, "npm", (), expect=True),
        E("c", "1", 3, None, "npm", ("sha1-x",), expect=True, weak=True),
        E("d", "1", 4, "https://github.com/x/d", "npm", git=True, pinned=False),
        E("e", "1", 5, None, "npm", (h(),), expect=True, install=True, transitive=True),
        E("f", "1", 6, None, "npm", (h(),), expect=True, install=True, transitive=False),
        E("g", "1", 7, "file:x.tgz", "npm"),
    ]
    got = rules.state_findings("package-lock.json", entries, (), "allowlist note")
    assert [(f.rule, f.line) for f in got] == [
        (model.SOURCE, 1),
        (model.MISSING, 2),
        (model.WEAK, 3),
        (model.SOURCE, 4),
        (model.UNPINNED, 4),
        (model.INSTALL, 5),
        (model.SOURCE, 7),
    ]
    assert "allowlist note" in got[0].message
    assert got[0].key == f"{model.SOURCE}|a@1|evil.example"
    assert got[-1].key == f"{model.SOURCE}|g@1|file"
    odd = rules.state_findings("x", [E("h", "1", 1, "../dir", "npm")], (), "")
    assert odd[0].key.endswith("|path")


@pytest.mark.parametrize(
    ("old", "new", "strict", "changed"),
    [
        ({"sha512-A"}, {"sha512-B"}, True, True),
        ({"sha512-A"}, {"sha512-A", "sha512-B"}, True, True),  # npm accepts any listed sha512
        ({"sha256:a"}, {"sha256:a", "sha256:b"}, False, False),  # a new wheel
        ({"sha256:a"}, {"sha256:b"}, False, True),
        ({"sha1-A"}, {"sha512-B"}, True, False),  # an upgrade, not a replacement
        ({"sha512-A"}, {"sha1-B"}, True, True),  # a downgrade
        ({"berry8/aa"}, {"berry10c0/bb"}, True, False),  # a new Berry cache key recomputes every checksum
        ({"berry8/aa"}, {"berry8/bb"}, True, True),
        ({"aa"}, {"bb"}, True, True),  # Cargo, NuGet, composer: one hash, no algorithm prefix
        (set(), {"sha512-A"}, True, False),
        ({"sha512-A"}, set(), True, False),  # a dropped hash is the missing-hash rule's
    ],
)
def test_replaced_compares_like_with_like(old: set, new: set, strict: bool, changed: bool) -> None:
    assert rules.replaced(old, new, strict=strict) is changed


def test_delta_findings_catch_replaced_hashes_and_dropped_go_modules() -> None:
    before = [E("a", "1", 1, integrity=("x",)), E("b", "1", 2, integrity=("y",)), E("c", "1", 3, integrity=("z",))]
    now = [E("a", "1", 1, integrity=("x2",)), E("b", "1", 2, integrity=("y", "y2"), eco="pypi"), E("d", "1", 4)]
    got = rules.delta_findings("go.sum", now, before)
    assert [f.rule for f in got] == [model.CHANGED, model.REMOVED]
    assert "c" in got[1].message
    assert [f.rule for f in rules.delta_findings("Cargo.lock", now, before)] == [model.CHANGED]
    assert rules.delta_findings("go.sum", before, before) == []
    bumped = [E("c", "2", 3, integrity=("w",)), *before[:2]]
    assert rules.delta_findings("go.sum", bumped, before) == []  # go mod tidy drops an old version's lines


def test_a_default_npm_registry_url_must_name_its_package() -> None:
    ok = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    assert sources.problem(ok, "npm", (), name="left-pad") == ""
    assert sources.problem(ok, "npm", (), name="") == ""
    scoped = "https://registry.npmjs.org/@s/p/-/p-1.0.0.tgz"
    assert sources.problem(scoped, "npm", (), name="@s/p") == ""
    assert sources.problem("https://registry.npmjs.org/@s%2Fp/-/p-1.0.0.tgz", "npm", (), name="@s/p") == ""
    for bad in (
        "https://registry.npmjs.org/evil-pad/-/evil-pad-6.6.6.tgz",
        "https://registry.npmjs.org/left-pad/-/../../evil/-/evil.tgz",
        "https://registry.npmjs.org/left-pad",
    ):
        assert "another package" in sources.problem(bad, "npm", (), name="left-pad")
    assert sources.problem("https://npm.internal.example/x.tgz", "npm", ALLOW, name="left-pad") == ""
