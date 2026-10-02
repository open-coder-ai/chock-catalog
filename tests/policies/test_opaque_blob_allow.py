"""opaque-blob-guard: the allowlist, symlinks, index versus working tree, and the agent events."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from policies import blobkit, scriptkit

gate, ns = blobkit.load()
XZ = b"\xfd7zXZ\x00" + b"\0" * 24
PATH = "testdata/a.xz"
ALLOW = ".chock/blob-allowlist.txt"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry(data: bytes = XZ, path: str = PATH) -> str:
    return f"{sha(data)}  {path}\n"


def rules_for(tmp_path: Path, files: dict, paths: list[str] | None = None, **kw: object) -> list[tuple[str, str]]:
    head = kw.pop("head", None)
    repo = blobkit.make_repo(tmp_path, files, head)  # type: ignore[arg-type]
    return blobkit.rules(blobkit.run(gate, repo, files if paths is None else paths, **kw))  # type: ignore[arg-type]


def test_an_allowlisted_blob_with_the_right_sha_and_path_is_allowed(tmp_path: Path) -> None:
    assert rules_for(tmp_path, {PATH: XZ, ALLOW: "# why: fixture\n\n" + entry()}) == []


def test_the_right_path_with_the_wrong_sha_asks(tmp_path: Path) -> None:
    found = rules_for(tmp_path, {PATH: XZ, ALLOW: entry(b"other")})
    assert found == [(PATH, "opaque-magic")]


def test_the_right_sha_at_another_path_asks(tmp_path: Path) -> None:
    assert rules_for(tmp_path, {PATH: XZ, ALLOW: entry(path="testdata/b.xz")}) == [(PATH, "opaque-magic")]


def test_a_file_edited_after_it_was_allowlisted_asks_again(tmp_path: Path) -> None:
    head = {PATH: XZ, ALLOW: entry()}
    assert rules_for(tmp_path, {PATH: XZ + b"1"}, head=head) == [(PATH, "opaque-magic")]


def test_sha256sum_binary_marker_and_crlf_are_read(tmp_path: Path) -> None:
    text = f"{sha(XZ)} *{PATH}\r\n"
    assert rules_for(tmp_path, {PATH: XZ, ALLOW: text}) == []


MALFORMED = {
    "short hash": f"{sha(XZ)[:-1]}  {PATH}\n",
    "upper-case hash": f"{sha(XZ).upper()}  {PATH}\n",
    "no path": f"{sha(XZ)}  \n",
    "one space": f"{sha(XZ)} {PATH}\n",
    "dotdot": f"{sha(XZ)}  testdata/../{PATH}\n",
    "absolute": f"{sha(XZ)}  /{PATH}\n",
    "dot slash": f"{sha(XZ)}  ./{PATH}\n",
    "backslash": f"{sha(XZ)}  testdata\\a.xz\n",
    "double slash": f"{sha(XZ)}  testdata//a.xz\n",
    "trailing slash": f"{sha(XZ)}  testdata/\n",
    "prose": "this is not an entry\n",
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_one_malformed_line_ignores_the_whole_list(tmp_path: Path, name: str) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ, ALLOW: entry() + MALFORMED[name]})
    found = blobkit.run(gate, repo, [PATH, ALLOW])
    assert blobkit.rules(found) == [(ALLOW, "allowlist-malformed"), (PATH, "opaque-magic")]
    assert "allowlist ignored: allowlist line 2" in found[1]["message"]


def test_a_malformed_list_is_silent_when_the_change_does_not_touch_it(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {ALLOW: "junk\n"})
    assert blobkit.run(gate, repo, ["tests/a.txt"], writes={"tests/a.txt": "x"}) == []


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"\xff\xfe\x00bad", id="not-utf8"),
        pytest.param(b"a\0b", id="nul"),
        pytest.param(entry().encode() + b"#" * (1 << 20), id="oversized"),
    ],
)
def test_an_unreadable_or_oversized_list_is_ignored(tmp_path: Path, content: bytes) -> None:
    found = rules_for(tmp_path, {PATH: XZ, ALLOW: content}, [PATH, ALLOW])
    assert found == [(ALLOW, "allowlist-malformed"), (PATH, "opaque-magic")]


def test_an_unstaged_list_approves_nothing(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ})
    scriptkit.write(repo, {ALLOW: entry()})
    assert blobkit.rules(blobkit.run(gate, repo, [PATH])) == [(PATH, "opaque-magic")]


def test_a_symlinked_list_is_read_as_the_text_of_the_link(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ})
    (repo / ".chock").mkdir()
    os.symlink(tmp_path / "outside.txt", repo / ALLOW)
    scriptkit.git(repo, "add", "-A")
    found = blobkit.run(gate, repo, [PATH, ALLOW])
    assert blobkit.rules(found) == [(ALLOW, "allowlist-malformed"), (PATH, "opaque-magic")]


def test_a_root_below_the_git_top_level_still_reads_the_index_and_head(tmp_path: Path) -> None:
    top = scriptkit.init_repo(tmp_path / "top", {"pkg/.chock/blob-allowlist.txt": entry(path="testdata/b.xz")})
    scriptkit.write(top, {"pkg/testdata/a.xz": XZ})
    scriptkit.git(top, "add", "-A")
    (top / "pkg/testdata/a.xz").write_text("clean\n")
    root = top / "pkg"
    assert blobkit.rules(blobkit.run(gate, root, [PATH])) == [(PATH, "opaque-magic")]
    head = blobkit.run(gate, root, [PATH], event="agent-commit")
    assert blobkit.rules(head) == [(PATH, "opaque-magic")]


def test_a_repo_root_that_is_not_a_folder_is_refused_not_passed(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        gate.findings({"event": "commit", "repo_root": str(tmp_path / "missing"), "writes": {PATH: ""}})


def test_an_absolute_path_under_a_symlinked_root_is_judged(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ})
    link = tmp_path / "alias"
    os.symlink(repo, link)
    found = gate.findings({"event": "commit", "repo_root": str(link), "writes": {f"{repo}/{PATH}": ""}})
    assert blobkit.rules(found) == [(PATH, "opaque-magic")]


def test_a_person_s_commit_honours_the_working_list(tmp_path: Path) -> None:
    assert rules_for(tmp_path, {PATH: XZ, ALLOW: entry()}, event="commit") == []
    assert rules_for(tmp_path / "ci", {PATH: XZ, ALLOW: entry()}, event="ci") == []


@pytest.mark.parametrize("event", ["tool_use", "agent-commit"])
def test_an_agent_cannot_approve_its_own_blob(tmp_path: Path, event: str) -> None:
    writes = {PATH: XZ.decode("latin-1"), ALLOW: entry()}
    found = rules_for(tmp_path, {PATH: XZ, ALLOW: entry()}, event=event, writes=writes)
    assert found == [(PATH, "opaque-magic")]


@pytest.mark.parametrize("event", ["tool_use", "agent-commit"])
def test_an_entry_already_committed_is_honoured_for_an_agent(tmp_path: Path, event: str) -> None:
    head = {ALLOW: entry()}
    found = rules_for(tmp_path, {PATH: XZ}, event=event, head=head, writes={PATH: XZ.decode("latin-1")})
    assert found == []


def test_an_agent_with_no_committed_list_gets_no_waiver(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "bare")
    scriptkit.write(repo, {PATH: XZ, ALLOW: entry()})
    assert blobkit.rules(blobkit.run(gate, repo, [PATH], event="agent-commit")) == [(PATH, "opaque-magic")]


def test_an_unhashed_blob_can_never_be_allowlisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ns.source, "HASH_CAP", 100)
    big = XZ + b"\0" * 100
    assert rules_for(tmp_path, {PATH: big, ALLOW: entry(big)}) == [(PATH, "opaque-magic")]


def test_a_symlink_out_of_the_repository_asks_and_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "outside.xz"
    target.write_bytes(XZ)
    repo = blobkit.make_repo(tmp_path, {"tests/x.txt": "x\n"})
    os.symlink(target, repo / "tests/link.dat")
    scriptkit.git(repo, "add", "-A")
    found = blobkit.run(gate, repo, ["tests/link.dat"])
    assert blobkit.rules(found) == [("tests/link.dat", "symlink-outside")]
    assert "outside the repository" in found[0]["message"]


def test_a_link_through_a_folder_asks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.xz").write_bytes(XZ)
    repo = blobkit.make_repo(tmp_path, {"README.md": "x\n"})
    os.symlink(tmp_path / "nowhere", repo / "tests-link")
    os.symlink(outside, repo / "fixtures")
    found = blobkit.run(gate, repo, [], writes={"fixtures/a.xz": "", "vendor/gone": ""})
    assert blobkit.rules(found) == [("fixtures/a.xz", "symlink-outside")]


def test_a_symlink_inside_the_repository_is_not_followed_and_not_a_finding(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {"src/a.xz": XZ})
    os.symlink(repo / "src/a.xz", repo / "tests-a")
    (repo / "tests").mkdir()
    os.symlink(repo / "src/a.xz", repo / "tests/a.dat")
    assert blobkit.run(gate, repo, ["tests/a.dat"], event="tool_use", writes={"tests/a.dat": "x"}) == []


def test_a_read_that_fails_midway_is_unreadable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "f").write_bytes(b"abc")

    def boom(*_args: object) -> bytes:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(ns.source.os, "read", boom)
    with pytest.raises(ns.source.Unreadable, match="Input/output error"):
        ns.source.read_disk(str(tmp_path), "f")


def test_a_staged_blob_cannot_hide_behind_a_clean_working_copy(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ})
    (repo / PATH).write_text("clean\n")
    assert blobkit.rules(blobkit.run(gate, repo, [PATH])) == [(PATH, "opaque-magic")]


def test_a_working_blob_staged_clean_is_found_on_disk(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: "clean\n"})
    (repo / PATH).write_bytes(XZ)
    assert blobkit.rules(blobkit.run(gate, repo, [PATH])) == [(PATH, "opaque-magic")]


def test_a_blob_deleted_from_the_working_tree_but_staged_is_found(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ})
    (repo / PATH).unlink()
    assert blobkit.rules(blobkit.run(gate, repo, [PATH])) == [(PATH, "opaque-magic")]


def test_the_same_content_in_both_places_is_one_finding(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ})
    assert len(blobkit.run(gate, repo, [PATH])) == 1


def test_an_unstaged_new_file_is_found_on_disk_only(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {})
    scriptkit.write(repo, {PATH: XZ})
    assert blobkit.rules(blobkit.run(gate, repo, [PATH])) == [(PATH, "opaque-magic")]


def test_a_missing_path_is_nothing_to_judge(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {})
    assert blobkit.run(gate, repo, ["tests/none.xz"]) == []


def test_a_pending_text_write_is_judged_as_the_bytes_it_will_become(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {})
    writes = {"fixtures/a.dat": "PK\x03\x04 payload", "fixtures/ok.dat": "plain", "fixtures/m.dat": "café"}
    found = blobkit.run(gate, repo, [], event="tool_use", writes=writes)
    assert blobkit.rules(found) == [("fixtures/a.dat", "opaque-magic")]


def test_at_the_turns_end_a_binary_on_disk_is_judged(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {})
    scriptkit.write(repo, {PATH: XZ})
    found = blobkit.run(gate, repo, [], event="tool_use", writes={PATH: XZ.decode("latin-1")})
    assert blobkit.rules(found) == [(PATH, "opaque-magic")]


def test_git_missing_leaves_only_the_working_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = blobkit.make_repo(tmp_path, {PATH: XZ})
    monkeypatch.setattr(ns.source, "GIT", None)
    assert blobkit.rules(blobkit.run(gate, repo, [PATH])) == [(PATH, "opaque-magic")]
    monkeypatch.setattr(ns.source, "GIT", str(tmp_path / "no-such-git"))
    assert blobkit.rules(blobkit.run(gate, repo, [PATH])) == [(PATH, "opaque-magic")]


def test_a_git_object_is_read_at_most_to_the_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = blobkit.make_repo(tmp_path, {"big": b"\0" * 300_000})
    monkeypatch.setattr(ns.source, "HEAD_CAP", 1000)
    monkeypatch.setattr(ns.source, "HASH_CAP", 70_000)
    blob = ns.source.read_git(str(repo), ":big")
    assert (len(blob.head), blob.size > 70_000, blob.sha) == (1000, True, None)
    assert ns.source.read_git(str(repo), ":absent") is None


@pytest.mark.parametrize(
    ("path", "want"),
    [
        ("tests/a.xz", "tests/a.xz"),
        ("tests\\a.xz", "tests/a.xz"),
        ("tests/../src/a.xz", "src/a.xz"),
        ("./tests/a.xz", "tests/a.xz"),
        ("/work/repo/tests/a.xz", "tests/a.xz"),
        ("/elsewhere/tests/a.xz", None),
        ("../tests/a.xz", None),
        ("..", None),
        (".", None),
    ],
)
def test_paths_are_normalised_inside_the_repository(path: str, want: str | None) -> None:
    assert ns.judge.normalize(path, "/work/repo/") == want
