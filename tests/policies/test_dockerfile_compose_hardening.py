"""dockerfile-compose-security: a waiver at ci, an unreadable HEAD copy, a renamed service and the floating tags (H-9)."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import dockerkit, scriptkit
from policies.dockerreview import BASE, LEGACY_COMPOSE, LONG, PIN, compose, engine, judged, mod

person = dockerkit.person

from dkscan import images  # noqa: E402  (the policy's own copy, on the path once the gate is loaded)

WAIVED_DOCKERFILE = BASE + "USER root  # chock: allow dk-last-user-root\n"
WAIVED_COMPOSE = compose("    privileged: true  # chock: allow cm-privileged-caps\n")


@pytest.mark.usefixtures("person")
@pytest.mark.parametrize("event", ["commit", "push", "ci"])
@pytest.mark.parametrize(("path", "text"), [("Dockerfile", WAIVED_DOCKERFILE), ("compose.yaml", WAIVED_COMPOSE)])
def test_a_waiver_is_honoured_where_a_person_judges(event: str, path: str, text: str) -> None:
    assert judged(None, {path: text}, event)[0] == "allow"


@pytest.mark.usefixtures("person")
@pytest.mark.parametrize("event", ["agent-commit", "tool_use", "stop"])
@pytest.mark.parametrize(("path", "text"), [("Dockerfile", WAIVED_DOCKERFILE), ("compose.yaml", WAIVED_COMPOSE)])
def test_a_waiver_is_not_honoured_for_an_agent(event: str, path: str, text: str) -> None:
    assert judged(None, {path: text}, event)[0] == "block"


@pytest.mark.usefixtures("person")
def test_a_waiver_naming_another_rule_is_not_honoured_at_ci() -> None:
    assert judged(None, {"Dockerfile": WAIVED_DOCKERFILE.replace("last-user-root", "tls-off")}, "ci")[0] == "block"


@pytest.mark.parametrize("event", ["pre-commit", "ci"])
def test_the_engine_honours_a_waiver_at_ci_and_refuses_it_at_an_agents_commit(
    event: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the runner, in a shell that is an agent's: a commit there is refused, the pipeline's check is not."""
    monkeypatch.delenv("CHOCK_AGENT_COMMIT", raising=False)
    monkeypatch.delenv("AI_AGENT", raising=False)
    monkeypatch.setenv("CLAUDECODE", "1")
    repo = scriptkit.init_repo(tmp_path / "repo", {"README.txt": "x\n"})
    scriptkit.write(repo, {"Dockerfile": WAIVED_DOCKERFILE})
    scriptkit.git(repo, "add", "-A")
    if event == "ci":
        scriptkit.git(repo, "commit", "-q", "-m", "change")
        assert engine(repo, "ci", base="HEAD~1") == 0
    else:
        assert engine(repo, "pre-commit") == 1


@pytest.mark.parametrize("kind", ["tab", "oversize"])
def test_a_compose_file_unreadable_in_head_does_not_absolve_what_a_change_adds(kind: str) -> None:
    if kind == "tab":
        head, grown = (
            "services:\n\tapp:\n\t\timage: x\n",
            "services:\n\tapp:\n\t\timage: x\n\tdb:\n\t\tprivileged: true\n",
        )
    else:
        head = LONG * 14000 + compose("")
        grown = head + "  db:\n    image: x\n    privileged: true\n"
    for event in ("commit", "ci"):
        verdict, rules = judged({"compose.yaml": head}, {"compose.yaml": grown}, event)
        assert (verdict, rules) == ("block", {"cm-unreadable"}), (event, verdict, rules)


def test_an_unreadable_finding_is_not_new_in_the_baseline_run() -> None:
    payload = {"event": "commit", "repo_root": dockerkit.BARE, "writes": {"compose.yaml": "services:\n\tapp:\n"}}
    assert [f.get("new") for f in mod.findings(payload)] == [True]
    assert [f.get("new") for f in mod.findings({**payload, "baseline": True})] == [None]


def test_a_second_service_with_the_same_weakness_is_new_after_a_rename() -> None:
    renamed = LEGACY_COMPOSE.replace("cache:", "store:")
    twice = renamed + "  other:\n    image: redis:latest\n    privileged: true\n"
    assert judged({"compose.yaml": LEGACY_COMPOSE}, {"compose.yaml": renamed})[0] == "allow"
    verdict, rules = judged({"compose.yaml": LEGACY_COMPOSE}, {"compose.yaml": twice})
    assert (verdict, "cm-privileged-caps" in rules) == ("block", True)


@pytest.mark.parametrize(
    ("ref", "verdict"),
    [
        ("python:3.12.4-slim", "pinned"),
        ("postgres:16.4", "pinned"),
        ("ubuntu:22.04", "pinned"),
        ("node:20", "pinned"),
        ("registry.example.com:5000/team/app:1.2", "pinned"),
        ("ubuntu", "floating"),
        ("ubuntu:latest", "floating"),
        ("a:LATEST", "floating"),
        ("debian:stable", "floating"),
        ("alpine:edge", "floating"),
        ("node:lts", "floating"),
        ("ubuntu:rolling", "floating"),
        ("app:nightly", "floating"),
        ("scratch", "scratch"),
        (f"ubuntu:latest{PIN}", "pinned"),
        ("debian:stable-slim", "floating"),
        ("node:lts-alpine", "floating"),
        ("python:slim", "floating"),
        ("golang:alpine", "floating"),
        ("redis:alpine", "floating"),
        ("nginx:mainline", "floating"),
        ("app:beta", "floating"),
        ("app:dev", "floating"),
        ("debian:bookworm", "pinned"),
        ("debian:bookworm-slim", "pinned"),
        ("ubuntu:jammy", "pinned"),
        ("ubuntu:noble", "pinned"),
        ("debian:bookworm-20240812-slim", "pinned"),
        ("alpine:3.20", "pinned"),
        ("app:1.0.0-beta.1", "pinned"),
        (f"python:slim{PIN}", "pinned"),
    ],
)
def test_a_tag_floats_by_its_components_and_a_release_needs_a_digit_or_a_codename(ref: str, verdict: str) -> None:
    assert images.judge(ref) == verdict


@pytest.mark.parametrize(
    "image", ["debian:stable-slim", "node:lts-alpine", "python:slim", "golang:alpine", "redis:alpine", "nginx:mainline"]
)
def test_a_floating_word_hidden_by_a_variant_is_caught_in_a_dockerfile_and_in_compose(image: str) -> None:
    assert judged(None, {"Dockerfile": f"FROM {image}\nUSER 1000\n"}) == ("block", {"dk-from-floating"})
    assert judged(None, {"compose.yaml": f"services:\n  a:\n    image: {image}\n"}) == ("ask", {"cm-image-floating"})


@pytest.mark.parametrize(
    "image",
    [
        "python:3.12.4-slim",
        f"debian:bookworm{PIN}",
        "node:20",
        "postgres:16.4",
        "alpine:3.20",
        "debian:bookworm-20240812-slim",
    ],
)
def test_a_version_or_a_digest_or_a_release_codename_is_allowed(image: str) -> None:
    assert judged(None, {"Dockerfile": f"FROM {image}\nUSER 1000\n"})[0] == "allow"
    assert judged(None, {"compose.yaml": f"services:\n  a:\n    image: {image}\n"})[0] == "allow"
