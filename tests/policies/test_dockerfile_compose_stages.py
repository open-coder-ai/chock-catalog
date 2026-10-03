"""dockerfile-compose-security: stage-aware image pins and the final stage's user (HP06 stage-aware script)."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import dockerkit

mod = dockerkit.load()

from dkscan import images, stages  # noqa: E402

USER = "USER 1000\n"


def found(text: str, path: str = "Dockerfile", root: str = dockerkit.BARE) -> list[tuple[str, int]]:
    payload = {"event": "tool_use", "repo_root": root, "writes": {path: text}}
    return [(f["rule"], f["line"]) for f in mod.findings(payload)]


def rules(text: str, root: str = dockerkit.BARE) -> set[str]:
    return {rule for rule, _ in found(text, root=root)}


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("FROM ubuntu\n", "dk-from-floating"),
        ("from ubuntu as build\nFROM build\n", "dk-from-floating"),
        ("FROM --platform=$BUILDPLATFORM node AS b\n", "dk-from-floating"),
        ("FROM node:20\n", "dk-from-no-digest"),
        ("FROM registry.example.com:5000/team/app:1.2\n", "dk-from-no-digest"),
        ("ARG BASE\nFROM ${BASE}\n", "dk-from-unresolved"),
        ("ARG V\nFROM node:$V\n", "dk-from-unresolved"),
        ("FROM $UNDECLARED\n", "dk-from-unresolved"),
        ("ARG BASE=debian\nFROM ${BASE}\n", "dk-from-floating"),
        ("ARG BASE=debian:12\nFROM ${BASE}\n", "dk-from-no-digest"),
        ("ARG T\nFROM debian:${T:-12}\n", "dk-from-no-digest"),
        ("ARG T\nFROM debian${T:+:12}\n", "dk-from-unresolved"),
        ("ARG T=1\nFROM debian${T:+:12}\n", "dk-from-no-digest"),
        ("FROM a:1@sha256:" + "0" * 64 + " AS a\nCOPY --from=nginx /x /y\n", "dk-from-floating"),
        ("FROM a:1@sha256:" + "0" * 64 + "\nCOPY --from=nginx:1.27 /x /y\n", "dk-from-no-digest"),
        ("FROM a:1@sha256:" + "0" * 64 + "\nRUN --mount=type=bind,from=alpine,target=/m true\n", "dk-from-floating"),
        ("FROM a:1@sha256:" + "0" * 64 + "\nCOPY --from=5 /x /y\n", "dk-from-floating"),
        ("FROM a:1@sha256:" + "0" * 64 + "\nARG IMG\nCOPY --from=$IMG /x /y\n", "dk-from-unresolved"),
    ],
)
def test_image_findings(text: str, rule: str) -> None:
    assert rule in rules(text + USER)


@pytest.mark.parametrize(
    "text",
    [
        "FROM scratch\n",
        "FROM node:20@sha256:" + "a" * 64 + "\n",
        "FROM node@sha256:" + "a" * 64 + " AS build\nFROM build\nFROM BUILD\n",
        "FROM node@sha256:" + "a" * 64 + " AS build\nCOPY --from=build /a /b\nCOPY --from=0 /a /b\n",
        "FROM node@sha256:" + "a" * 64 + " AS b\nRUN --mount=type=cache,from=b,target=/c true\n",
        "ARG B=node@sha256:" + "a" * 64 + "\nFROM $B\n",
    ],
)
def test_pinned_images_scratch_and_stages_are_silent(text: str) -> None:
    assert not {r for r in rules(text + USER) if r.startswith("dk-from")}


@pytest.mark.parametrize(
    "line",
    [
        "FROM ubuntu:" + "late" + "st\n",
        "from --platform=linux/amd64 ubuntu:" + "late" + "st\n",
        "FROM ghcr.io/org/app\n",
        "FROM ghcr.io/org/app AS build\n",
        "FROM ${REG}/app\n",
    ],
)
def test_forms_block_unpinned_agent_components_reads_are_left_to_it_where_installed(line: str, tmp_path: Path) -> None:
    assert {r for r in rules(line + USER) if r.startswith("dk-from")}
    root = dockerkit.installed(tmp_path, dockerkit.PINS)
    assert not {r for r in rules(line + USER, root) if r.startswith("dk-from")}


def test_latest_on_a_continued_from_line_is_reported_here() -> None:
    text = "FROM \\\n  ubuntu:" + "late" + "st\n" + USER
    assert ("dk-from-floating", 1) in found(text)


def test_a_stage_named_like_an_image_shadows_it() -> None:
    text = "FROM node:20@sha256:" + "a" * 64 + " AS node\nFROM node\n" + USER
    assert not {r for r in rules(text) if r.startswith("dk-from")}


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("FROM a@sha256:" + "0" * 64 + "\n", 1),
        ("FROM a@sha256:" + "0" * 64 + "\nUSER root\n", 2),
        ("FROM a@sha256:" + "0" * 64 + "\nUSER 0:0\n", 2),
        ("FROM a@sha256:" + "0" * 64 + "\nUSER ROOT\n", 2),
        ("FROM a@sha256:" + "0" * 64 + "\nUSER 1000\nUSER root\n", 3),
        ("FROM a@sha256:" + "0" * 64 + " AS b\nUSER 1000\nFROM b\nUSER root\n", 4),
        ("FROM a@sha256:" + "0" * 64 + " AS b\nUSER root\nFROM b\n", 2),
        ("FROM a@sha256:" + "0" * 64 + "\nARG U\nUSER $U\n", 3),
        ("FROM a@sha256:" + "0" * 64 + "\nARG U=root\nUSER ${U}\n", 3),
        ("ARG U=0\nFROM a@sha256:" + "0" * 64 + "\nARG U\nUSER $U\n", 4),
        ("FROM a@sha256:" + "0" * 64 + "\nUSER 1000\nFROM b@sha256:" + "0" * 64 + "\n", 3),
    ],
)
def test_final_stage_root_or_no_user(text: str, line: int) -> None:
    assert ("dk-last-user-root", line) in found(text)


@pytest.mark.parametrize(
    "text",
    [
        "FROM a@sha256:" + "0" * 64 + "\nUSER 1000\n",
        "FROM a@sha256:" + "0" * 64 + "\nUSER app:app\n",
        "FROM a@sha256:" + "0" * 64 + "\nENV U=app\nUSER $U\n",
        "FROM a@sha256:" + "0" * 64 + " AS b\nUSER 1000\nFROM b\n",
        "FROM a@sha256:" + "0" * 64 + " AS b\nENV U=app\nFROM b\nUSER $U\n",
        "FROM root@sha256:" + "0" * 64 + "\nUSER root\nFROM gcr.io/distroless/static:nonroot\n",
        "FROM docker:27-dind-rootless\n",
        "FROM app:1-nonroot\n",
        "# a file with no FROM\n",
        "ENV A=1\nFROM\nUSER 1000\n",
        "USER root\n",
    ],
)
def test_non_root_final_stage_is_silent(text: str) -> None:
    assert "dk-last-user-root" not in rules(text)


@pytest.mark.parametrize("base", ["evil/nonroot-ish:1", "rootless/app:1", "a:nonrootx"])
def test_non_root_is_read_from_the_tag_only(base: str) -> None:
    assert "dk-last-user-root" in rules(f"FROM {base}@sha256:" + "0" * 64 + "\n")


def test_bom_does_not_hide_the_first_stage() -> None:
    assert {"dk-from-no-digest", "dk-last-user-root"} <= rules("\ufeffFROM ubuntu:22.04\n")


def test_arg_and_env_before_any_stage_or_user() -> None:
    walker = stages.Walker()
    assert walker.scope() == {}
    assert stages.walk([]) == []


def test_env_legacy_form_and_words_fallback() -> None:
    assert stages.env_pairs("A b c") == [("A", "b c")]
    assert stages.env_pairs('A="x y" B=z') == [("A", "x y"), ("B", "z")]
    assert stages.words("a 'b") == ["a", "'b"]


def test_substitute_forms() -> None:
    env = {"A": "x", "N": None}
    assert images.substitute("$A-${A}", env) == "x-x"
    assert images.substitute("${N:-d}", env) == "d"
    assert images.substitute("${A:+w}", env) == "w"
    assert images.substitute("${M:+w}", env) == ""
    assert images.substitute("${N}", env) is None
    assert images.substitute("${N:?e}", env) is None
    assert images.substitute("${A:-${B}}", env) is None


def test_split_ref_and_judge() -> None:
    assert images.split_ref("host:5000/a/b") == ("host:5000/a/b", "", "")
    assert images.split_ref("a:1@sha256:" + "f" * 64) == ("a", "1", "@sha256:" + "f" * 64)
    assert images.judge("SCRATCH") == "scratch"
    assert images.judge("a:" + "late" + "st") == "floating"
    assert images.judge("a:LATEST") == "no-digest"
