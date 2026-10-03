"""opaque-blob-guard: decode-and-evaluate build text, and the gradle wrapper jar."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from policies import blobkit, scriptkit

gate, ns = blobkit.load()
SUM_A = "a" * 64
SUM_B = "b" * 64
JAR = b"PK\x03\x04" + b"\0" * 24
PROPS = "gradle/wrapper/gradle-wrapper.properties"
WRAPPER = "gradle/wrapper/gradle-wrapper.jar"


def text_rules(tmp_path: Path, path: str, text: str) -> list[tuple[int, str]]:
    repo = blobkit.make_repo(tmp_path, {path: text})
    return [(f["line"], f["rule"]) for f in blobkit.run(gate, repo, [path])]


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        ('i=$(echo $x | tr "\\t \\-_" " \\t_\\-" | sed 1d)', "text-tr-swap-pipe"),
        ("x=`cat f | tr ' \\t_\\-' '\\t _\\-' | rev`", "text-tr-swap-pipe"),
        ("xz -d < tests/files/a.xz | sh", "text-decode-eval"),
        ("unxz -c f | eval", "text-decode-eval"),
        ("gzip -dc f | bash", "text-decode-eval"),
        ("zcat f | /bin/sh -s", "text-decode-eval"),
        ("base64 -d f | source /dev/stdin", "text-decode-eval"),
        ("base64 --decode f | .", "text-decode-eval"),
        ("uudecode -o /dev/stdout f | sh;", "text-decode-eval"),
        ("bzip2 -dc f | dash", "text-decode-eval"),
        ("openssl enc -d -aes-256-cbc -in f | sh", "text-decode-eval"),
        ("head -c 1024 tests/files/a.bin | sh", "text-slice-eval"),
        ("tail -c +31233 f | eval", "text-slice-eval"),
        ("dd if=f bs=1 skip=100 2>/dev/null | bash", "text-slice-eval"),
        ('eval "$(cat tests/files/payload.txt)"', "text-subst-eval"),
        ("eval `xz -dc < testdata/p.xz`", "text-subst-eval"),
        ('eval "$(sed 1d fixtures/p.sh)"', "text-subst-eval"),
        ("cat b | xz -F raw --lzma1 -dc | sh", "text-decode-eval"),
        ("xz --lzma1 -dc < b | /usr/bin/env bash", "text-decode-eval"),
        ("zcat b | sudo sh", "text-decode-eval"),
        ("lzcat b | python3", "text-decode-eval"),
        ("xxd -r -p b | sh", "text-decode-eval"),
        ("tail -c +31233 b | xz -F raw -dc | sh", "text-slice-eval"),
        ("bash <(xz -dc f)", "text-subst-eval"),
        ('sh -c "$(xz -dc f)"', "text-subst-eval"),
        ('eval "$(zcat f)"', "text-subst-eval"),
        (". <(base64 -d f)", "text-subst-eval"),
        ('. "$srcdir/tests/files/x.sh"', "text-run-test-file"),
        ("source tests/x.sh", "text-run-test-file"),
        ("sh fixtures/run", "text-run-test-file"),
    ],
)
def test_decode_and_evaluate_shapes_ask(tmp_path: Path, line: str, rule: str) -> None:
    found = text_rules(tmp_path, "m4/build.m4", f"AC_DEFUN([X], [\n{line}\n])\n")
    assert (2, rule) in found


@pytest.mark.parametrize(
    "line",
    [
        "tr '[a-z]' '[A-Z]' | sed 1d",
        "tr -d '\\r' < in | cat",
        'tr "\\t" " " > out',
        "xz -d < data.xz > data",
        "gzip -dc f | tar x",
        "head -c 16 /dev/urandom | od",
        'eval "$(cat config.site)"',
        "echo eval | sh -n",
        "echo \"$x\" | tr '\\012' ' ' | sed 1d",
        'tr "\\t" " " | sed 1d',
        "dd if=a of=b",
        "xz -9 < f | sha256sum",
        "# xz -d f | sh",
        "dnl xz -d f | sh",
        "bash ./build.sh",
    ],
)
def test_ordinary_autotools_text_is_allowed(tmp_path: Path, line: str) -> None:
    assert text_rules(tmp_path, "configure", f"#!/bin/sh\n{line}\n") == []


@pytest.mark.parametrize(
    "path",
    [
        "configure",
        "sub/configure",
        "configure.ac",
        "configure.in",
        "Makefile.am",
        "src/a.m4",
        "aclocal.m4",
        "Makefile",
        "libtool",
        "rules.mk",
        "bootstrap",
    ],
)
def test_build_texts_are_judged_wherever_they_sit(tmp_path: Path, path: str) -> None:
    assert text_rules(tmp_path, path, "xz -d < f | sh\n") == [(1, "text-decode-eval")]


@pytest.mark.parametrize("path", ["README.md", "src/main.sh", "tests/run.sh", "Rakefile", "configure.txt"])
def test_other_files_are_not_build_text(tmp_path: Path, path: str) -> None:
    assert text_rules(tmp_path, path, "xz -d < f | sh\n") == []


def test_a_line_continuation_does_not_hide_the_pipe(tmp_path: Path) -> None:
    found = text_rules(tmp_path, "m4/a.m4", "xz -d \\\n  < f \\\n  | sh\n")
    assert found == [(1, "text-decode-eval")]


def test_each_rule_reports_each_line_once(tmp_path: Path) -> None:
    found = text_rules(tmp_path, "m4/a.m4", "xz -d < f | sh\nok\nxz -d < g | sh | sh\n")
    assert found == [(1, "text-decode-eval"), (3, "text-decode-eval")]


def test_a_text_past_the_scan_cap_is_one_finding_not_a_pass(tmp_path: Path) -> None:
    text = "# padding\n" * 250_000 + "xz -d < f | sh\n"
    assert text_rules(tmp_path, "m4/a.m4", text) == [(1, "text-too-large")]


def test_invalid_utf8_is_still_scanned(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {"m4/a.m4": b"\xff\xfe junk\nxz -d < f | sh\n"})
    assert [(f["line"], f["rule"]) for f in blobkit.run(gate, repo, ["m4/a.m4"])] == [(2, "text-decode-eval")]


@pytest.mark.parametrize(
    "line",
    [
        "xz -" + "d" * 80_000,
        "zcat |" * 80_000,
        "xz -d | " * 60_000,
        "dd | a " * 60_000,
        'tr "' * 100_000,
        "eval $(" * 60_000,
    ],
    ids=["long-option", "sinks", "decoder-sinks", "dd-sinks", "tr-quotes", "evals"],
)
def test_hostile_text_is_scanned_in_bounded_work(tmp_path: Path, line: str) -> None:
    repo = blobkit.make_repo(tmp_path, {"m4/a.m4": line + "\n"})
    found = blobkit.run(gate, repo, ["m4/a.m4"])
    assert {f["rule"] for f in found} <= {
        "text-decode-eval",
        "text-slice-eval",
        "text-subst-eval",
        "text-too-dense",
        "text-tr-swap-pipe",
    }


@pytest.mark.parametrize("lead", ["# harmless \\", "dnl harmless \\"])
def test_a_comment_ending_in_a_backslash_does_not_hide_the_next_line(tmp_path: Path, lead: str) -> None:
    assert text_rules(tmp_path, "m4/a.m4", f"{lead}\nxz -d < f | sh\n") == [(2, "text-decode-eval")]


def test_dense_hostile_files_together_stay_well_inside_the_gate_clock(tmp_path: Path) -> None:
    shapes = ["xz a a a a a a a a a a gzip b b b b b | sh\n", "zcat bzcat xzcat | sh ", "bash -c $(", "| sh "]
    files = {f"m4/{i}.m4": shapes[i % 4] * (1_000_000 // len(shapes[i % 4])) for i in range(12)}
    repo = blobkit.make_repo(tmp_path, files)
    start = time.monotonic()
    found = blobkit.run(gate, repo, files)
    assert time.monotonic() - start < 20
    assert len(found) >= 12  # every one is a finding (match or too-dense), none a pass


def test_too_many_candidate_spots_is_a_finding_not_a_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ns.detect, "MAX_ANCHORS", 5)
    assert text_rules(tmp_path, "m4/a.m4", "| sh\n" * 6) == [(1, "text-too-dense")]


def test_a_gap_wider_than_the_window_is_the_stated_limit(tmp_path: Path) -> None:
    assert text_rules(tmp_path, "m4/a.m4", "xz -d " + " " * 2500 + "| sh\n") == []


def test_the_text_rule_also_runs_in_a_blob_folder(tmp_path: Path) -> None:
    assert text_rules(tmp_path, "tests/m4/b.m4", "xz -d < f | sh\n") == [(1, "text-decode-eval")]


def wrapper(tmp_path: Path, files: dict[str, str | bytes], head: dict[str, str | bytes] | None = None) -> list[str]:
    repo = blobkit.make_repo(tmp_path, files, head)
    writes = {p: t for p, t in files.items() if isinstance(t, str)}
    return [f["message"] for f in blobkit.run(gate, repo, files, writes={**{p: "" for p in files}, **writes})]


def test_a_changed_wrapper_jar_alone_asks(tmp_path: Path) -> None:
    (message,) = wrapper(tmp_path, {WRAPPER: JAR})
    assert "distributionSha256Sum" in message


def test_the_zip_signature_alone_is_not_a_second_finding_for_a_wrapper_jar(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {WRAPPER: JAR})
    assert blobkit.rules(blobkit.run(gate, repo, [WRAPPER])) == [(WRAPPER, "gradle-wrapper")]


def test_crlf_properties_are_read(tmp_path: Path) -> None:
    files = {WRAPPER: JAR, PROPS: f"distributionUrl=x\r\ndistributionSha256Sum={SUM_A}\r\n"}
    assert wrapper(tmp_path, files, {PROPS: "distributionUrl=x\r\n"}) == []


def test_a_new_sum_in_the_same_change_is_accepted(tmp_path: Path) -> None:
    files = {WRAPPER: JAR, PROPS: f"distributionSha256Sum={SUM_A}\n"}
    assert wrapper(tmp_path, files, {PROPS: "distributionUrl=x\n"}) == []


def test_a_changed_sum_is_accepted_and_case_does_not_matter(tmp_path: Path) -> None:
    files = {WRAPPER: JAR, PROPS: f"distributionSha256Sum = {SUM_B}\n"}
    assert wrapper(tmp_path, files, {PROPS: f"distributionSha256Sum={SUM_A}\n"}) == []
    same = {WRAPPER: JAR, PROPS: f"distributionSha256Sum={SUM_A.upper()}\nother=1\n"}
    assert len(wrapper(tmp_path / "again", same, {PROPS: f"distributionSha256Sum={SUM_A}\n"})) == 1


def test_an_unchanged_sum_does_not_vouch_for_a_new_jar(tmp_path: Path) -> None:
    files = {WRAPPER: JAR, PROPS: f"distributionSha256Sum={SUM_A}\nnote=1\n"}
    assert len(wrapper(tmp_path, files, {PROPS: f"distributionSha256Sum={SUM_A}\n"})) == 1


def test_properties_without_a_sum_or_a_short_sum_ask(tmp_path: Path) -> None:
    assert len(wrapper(tmp_path, {WRAPPER: JAR, PROPS: "distributionUrl=x\n"})) == 1
    assert len(wrapper(tmp_path / "short", {WRAPPER: JAR, PROPS: "distributionSha256Sum=abc\n"})) == 1


def test_a_sum_beside_another_wrapper_does_not_count(tmp_path: Path) -> None:
    files = {"app/" + WRAPPER: JAR, PROPS: f"distributionSha256Sum={SUM_A}\n"}
    assert len(wrapper(tmp_path, files)) == 1


def test_a_nested_wrapper_reads_its_own_properties(tmp_path: Path) -> None:
    files = {"app/" + WRAPPER: JAR, "app/" + PROPS: f"distributionSha256Sum={SUM_A}\n"}
    assert wrapper(tmp_path, files, {"app/" + PROPS: "x=1\n"}) == []


def test_a_known_wrapper_hash_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sha = ns.source.from_bytes(JAR).sha
    table = ns.tables.load()
    patched = table._replace(known_wrappers=frozenset({sha}))
    monkeypatch.setattr(ns.tables, "load", lambda: patched)
    assert wrapper(tmp_path, {WRAPPER: JAR}) == []


def test_a_wrapper_jar_that_is_an_executable_still_asks_twice(tmp_path: Path) -> None:
    repo = blobkit.make_repo(tmp_path, {WRAPPER: b"\x7fELF\x02\x01\x01" + b"\0" * 24})
    assert blobkit.rules(blobkit.run(gate, repo, [WRAPPER])) == [(WRAPPER, "opaque-magic"), (WRAPPER, "gradle-wrapper")]


def test_head_without_a_properties_file_counts_as_a_new_sum(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "bare")
    scriptkit.write(repo, {WRAPPER: JAR, PROPS: f"distributionSha256Sum={SUM_A}\n"})
    scriptkit.git(repo, "add", "-A")
    writes = {WRAPPER: "", PROPS: f"distributionSha256Sum={SUM_A}\n"}
    assert blobkit.run(gate, repo, [], writes=writes) == []
