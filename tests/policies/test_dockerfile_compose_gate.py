"""dockerfile-compose-security: which files are read, waivers, baseline keys, exit codes and run time."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from policies import dockerkit, scriptkit
from policies.dockerkit import person  # noqa: F401

POLICY, SCRIPT = "dockerfile-compose-security", "dockerfile-compose-security-gate.py"
mod = dockerkit.load()

PIN = "@sha256:" + "0" * 64
GOOD = f"FROM a:1{PIN}\nUSER 1000\n"


def rules(path: str, text: str, event: str = "tool_use", root: str = dockerkit.BARE) -> set[str]:
    return {f["rule"] for f in mod.findings({"event": event, "repo_root": root, "writes": {path: text}})}


@pytest.mark.parametrize(
    "path",
    [
        "Dockerfile",
        "svc/Dockerfile",
        "dockerfile",
        "Dockerfile.prod",
        "Dockerfile-dev",
        "build/app.Dockerfile",
        "Containerfile",
        "x/Containerfile.ci",
        "img.containerfile",
    ],
)
def test_dockerfile_names_are_read(path: str) -> None:
    assert rules(path, "FROM ubuntu\nUSER 1000\n") == {"dk-from-floating"}


@pytest.mark.parametrize(
    "path",
    [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.override.yaml",
        "x/compose.prod.yml",
        "Docker-Compose.YML",
    ],
)
def test_compose_names_are_read(path: str) -> None:
    assert rules(path, "services:\n  a:\n    image: nginx\n") == {"cm-image-floating"}


@pytest.mark.parametrize(
    "path",
    [
        "Dockerfile.md",
        "docs/dockerfile.txt",
        "dockerfile_lint.py",
        "Dockerfile.dockerignore",
        "my-compose.yaml",
        "compose.json",
        "README.md",
    ],
)
def test_other_files_are_not_read(path: str) -> None:
    assert not rules(path, "FROM ubuntu\nservices:\n  a:\n    privileged: true\n")


def test_non_text_write_is_skipped() -> None:
    assert mod.findings({"event": "tool_use", "writes": {"Dockerfile": None}}) == []


@pytest.mark.usefixtures("person")
def test_dockerfile_waiver_on_the_comment_above_or_the_instruction() -> None:
    text = f"FROM a:1{PIN}\n# chock: allow dk-tls-off\nRUN curl -k https://example.com\nRUN true \\\n  && wget --no-check-certificate x # chock: allow dk-tls-off\nUSER root\n"
    assert rules("Dockerfile", text, "commit") == {"dk-last-user-root"}
    assert rules("Dockerfile", text) == {"dk-tls-off", "dk-last-user-root"}


@pytest.mark.usefixtures("person")
def test_waiver_for_another_rule_does_not_count() -> None:
    text = f"FROM a:1{PIN}\n# chock: allow dk-sudo-sshd\nRUN curl -k https://example.com\nUSER 1000\n"
    assert rules("Dockerfile", text, "commit") == {"dk-tls-off"}


WAIVED = f"FROM a:1{PIN}\n# chock: allow dk-last-user-root\nUSER root\n"


@pytest.mark.usefixtures("person")
@pytest.mark.parametrize(("name", "value"), [("CHOCK_AGENT_COMMIT", "1"), ("CLAUDECODE", "1"), ("AI_AGENT", "x")])
def test_agent_commit_waiver_does_not_count(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    assert not rules("Dockerfile", WAIVED, "commit")
    monkeypatch.setenv(name, value)
    assert rules("Dockerfile", WAIVED, "commit") == {"dk-last-user-root"}


@pytest.mark.usefixtures("person")
def test_configured_agent_env_marks_an_agent_and_an_explicit_person_wins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".chock").mkdir()
    (tmp_path / ".chock" / "config.yaml").write_text(
        "rollout: enforce\nagent_commit_env:\n  # one per line\n\n  - MY_AGENT\nother: [A, B]\n", encoding="utf-8"
    )
    root = str(tmp_path)
    monkeypatch.setenv("MY_AGENT", "1")
    assert rules("Dockerfile", WAIVED, "commit", root) == {"dk-last-user-root"}
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", "0")
    assert not rules("Dockerfile", WAIVED, "commit", root)
    (tmp_path / ".chock" / "config.yaml").write_text(
        "agent_commit_env: [OTHER, 'MY_AGENT', bad-name]\n", encoding="utf-8"
    )
    monkeypatch.delenv("CHOCK_AGENT_COMMIT")
    monkeypatch.delenv("CLAUDECODE")
    assert rules("Dockerfile", WAIVED, "commit", root) == {"dk-last-user-root"}
    (tmp_path / ".chock" / "config.yaml").write_bytes(b"\xff\xfe")
    assert not rules("Dockerfile", WAIVED, "commit", root)


def test_keys_do_not_carry_line_numbers() -> None:
    before = mod.findings({"event": "commit", "writes": {"Dockerfile": "FROM ubuntu\n"}})
    after = mod.findings({"event": "commit", "writes": {"Dockerfile": "# moved\n\nFROM ubuntu\n"}})
    assert [f["key"] for f in before] == [f["key"] for f in after]
    assert before[0]["line"] != after[0]["line"]


def test_secret_value_is_not_echoed() -> None:
    (finding,) = mod.findings(
        {
            "event": "tool_use",
            "writes": {"compose.yaml": "services:\n  a:\n    environment:\n      DB_PASSWORD: hunter2\n"},
        }
    )
    assert "hunter2" not in finding["message"]
    assert "hunter2" not in finding["key"]


def run(writes: dict[str, str], cwd: Path) -> tuple[int, str, str]:
    proc = scriptkit.run_script_full(
        POLICY, SCRIPT, cwd, json.dumps({"event": "commit", "repo_root": str(cwd), "writes": writes})
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_exit_codes(tmp_path: Path) -> None:
    assert run({"Dockerfile": GOOD}, tmp_path)[0] == 0
    code, out, err = run({"Dockerfile": f"FROM a:1{PIN}\nUSER root\n"}, tmp_path)
    assert code == 1
    assert json.loads(out)["findings"][0]["rule"] == "dk-last-user-root"
    assert "Dockerfile:2: dk-last-user-root (CWE-250" in err
    assert "chock: allow <rule-id>" in err
    code, _, _ = run({"Dockerfile": "FROM node:20\nUSER 1000\n"}, tmp_path)
    assert code == 3


def test_unreadable_stdin_is_not_an_allow(tmp_path: Path) -> None:
    code, err = scriptkit.run_script(POLICY, SCRIPT, tmp_path, "not json")
    assert code == 2
    assert "not the gate JSON" in err


def test_unreadable_compose_message_has_no_cwe(tmp_path: Path) -> None:
    code, _, err = run({"compose.yaml": "a: *b\n"}, tmp_path)
    assert code == 1
    assert "cm-unreadable (unreadable;" in err


@pytest.mark.parametrize(
    "text",
    [
        "RUN " + "sudo env " * 40_000 + "\n",
        "RUN curl " + "| " * 40_000 + "\n",
        "RUN " + "git -c a " * 20_000 + "\n",
        "RUN " + "curl " * 40_000 + "\n",
        "RUN " + "a=b " * 40_000 + "\n",
        "RUN " + "x \\\n" * 20_000 + "\n",
        "RUN <<EOF\n" + "curl x | tee y |\n" * 20_000 + "EOF\n",
        "RUN chmod " + "-R " * 40_000 + "\n",
        "ENV " + "A" * 200_000 + "=1\n",
        "RUN " + "\"'" * 14_000 + "\n",
        "RUN " + "git clone x; " * 20_000 + "\n",
        "RUN " + "insecure " * 40_000 + "\n",
        "ENV " + " ".join(f"K{i}_PASSWORD=v" for i in range(5000)) + "\n",
    ],
    ids=lambda text: f"{text[:12]!r}x{len(text)}",
)
def test_large_crafted_dockerfiles_stay_fast(text: str) -> None:
    start = time.monotonic()
    mod.findings({"event": "tool_use", "writes": {"Dockerfile": "FROM a\n" + text}})
    assert time.monotonic() - start < 5


def test_large_compose_stays_fast() -> None:
    text = "services:\n" + "".join(f"  s{i}:\n    image: a:1{PIN}\n    ports: ['{i}:80']\n" for i in range(5000))
    start = time.monotonic()
    assert not mod.findings({"event": "tool_use", "writes": {"compose.yaml": text}})
    assert time.monotonic() - start < 5


def test_many_findings_at_commit_stay_fast() -> None:
    text = f"FROM a:1{PIN}\n" + "".join(f"RUN sudo x{i}\n" for i in range(20_000)) + "USER 1000\n"
    start = time.monotonic()
    assert len(mod.findings({"event": "commit", "writes": {"Dockerfile": text}})) == 20_000
    assert time.monotonic() - start < 5
