"""verify-dependency-exists: a fourth review's bypass and stall, each shown refused and silent on the correct form."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from policies import depkit, gatekit, scriptkit

POLICY = "verify-dependency-exists"
NAME = "dependency-manifests.py"
ALLOWLIST = ".chock/dependency-allowlist.txt"
gate, r = depkit.load()


def run(repo: Path, writes: dict[str, str]) -> tuple[int, list[str]]:
    payload = json.dumps({"event": "commit", "repo_root": str(repo), "writes": writes})
    proc = scriptkit.run_script_full(POLICY, NAME, repo, payload)
    return proc.returncode, [item["key"].split("|")[0] for item in json.loads(proc.stdout)["findings"]]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {ALLOWLIST: "requests\n"})


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_a_bom_encoded_requirements_file_is_asked_about_not_passed(repo: Path, encoding: str) -> None:
    mangled = "requests\nevil\n".encode(encoding).decode("utf-8", errors="replace")
    assert run(repo, {"requirements.txt": mangled}) == (3, ["unreadable"])


def test_the_same_requirements_in_utf8_are_read(repo: Path) -> None:
    assert run(repo, {"requirements.txt": "requests\n"}) == (0, [])
    assert run(repo, {"requirements.txt": "requests\nevil\n"}) == (1, ["py"])


def test_a_staged_utf16_requirements_file_is_refused_at_commit(tmp_path: Path) -> None:
    base = scriptkit.init_repo(tmp_path / "c", {ALLOWLIST: "requests\n", "README.md": "x\n"})
    scriptkit.write(base, {"requirements.txt": "requests\nevil\n".encode("utf-16")})
    scriptkit.git(base, "add", "requirements.txt")
    assert gatekit.judge(POLICY, base, gatekit.COMMIT)[0] != 0
    scriptkit.write(base, {"requirements.txt": "requests\n".encode()})
    scriptkit.git(base, "add", "requirements.txt")
    assert gatekit.judge(POLICY, base, gatekit.COMMIT)[0] == 0


@pytest.mark.parametrize("line", ["${EVIL_PKG}==1.0", "ev${X}il", "-e ${PKG}", "${A}${B}>=2 ; python_version>'3'"])
def test_a_name_pip_builds_from_an_environment_variable_is_judged_as_written(line: str) -> None:
    assert len(r.pyreq.requirement_names(line)) == 1


@pytest.mark.parametrize(
    "line",
    [
        "requests==${PINNED}",
        "requests @ ${URL}",
        "--index-url https://${TOKEN}@host/simple",
        "-r ${BASE}/requirements.txt",
        "-e ./${DIR}",
        "./${DIR}/pkg",
        "${DIR}/pkg-1.0.whl",
        "$(not-a-variable)",
        "${lowercase}",
    ],
)
def test_a_variable_in_a_version_option_or_local_path_is_not_a_package_name(line: str) -> None:
    assert r.pyreq.requirement_names(line) in ([], ["requests"])


def test_an_unlisted_variable_name_is_refused_and_a_listed_one_is_silent(repo: Path) -> None:
    assert run(repo, {"requirements.txt": "${EVIL_PKG}==1\nrequests\n"}) == (1, ["py"])
    assert run(repo, {"requirements.txt": "requests==${PINNED}\n"}) == (0, [])


@pytest.mark.parametrize("gap", [" ", "\n", "\t"])
@pytest.mark.parametrize("head", ["id", "id 'x.y'", 'id("x.y")', "id ('x.y') "])
def test_a_whitespace_run_after_a_plugin_id_is_linear(head: str, gap: str) -> None:
    start = time.monotonic()
    r.gradle.gradle_names(head + gap * 200_000)
    assert time.monotonic() - start < 5


def test_versioned_plugin_forms_are_still_read() -> None:
    text = (
        "id 'a.b' version '1'\nid(\"c.d\") version \"1\"\nid ( 'e.f' ) version '2'\nid('g.h')  version '1'\nid 'i.j'\n"
    )
    assert r.gradle.gradle_names(text) == ["plugin:a.b", "plugin:c.d", "plugin:e.f", "plugin:g.h"]


@pytest.mark.parametrize("gap", ["\n", " ", "\t", "\r\n"])
def test_a_run_of_blank_lines_in_mix_exs_is_linear(gap: str) -> None:
    start = time.monotonic()
    r.elixir.mix_names(gap * 200_000 + "x")
    assert time.monotonic() - start < 5


def test_mix_exs_comment_lines_are_still_dropped_and_code_after_blank_lines_is_read() -> None:
    text = '# {:a, "1"}\n  # {:b, "1"}\n{:c, "1"} # x\n\n\n   \n   # {:d, "2"}\n{:e, "1"}'
    assert r.elixir.mix_names(text) == ["c", "e"]
