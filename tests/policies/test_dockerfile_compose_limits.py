"""dockerfile-compose-security: what runs past the patterns' bounds is reported, never passed (review round 2)."""

from __future__ import annotations

import time

import pytest
from policies import dockerkit

mod = dockerkit.load()

from dkscan import limits  # noqa: E402

HEAD = "FROM a@sha256:" + "0" * 64 + "\n"
TAIL = "USER 1000\n"
PIPE = "|"


def rules(body: str) -> set[str]:
    payload = {"event": "tool_use", "repo_root": dockerkit.BARE, "writes": {"Dockerfile": HEAD + body + TAIL}}
    return {f["rule"] for f in mod.findings(payload)}


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ("RUN " + "A=1 " * 9 + "chmod 777 /x\n", "dk-chmod-setuid"),
        ("RUN " + "A=1 " * 9 + "sudo make\n", "dk-sudo-sshd"),
        ("RUN git " + "--no-pager " * 9 + "clone https://example.com/y\n", "dk-git-clone-unpinned"),
        ("RUN " + "A=1 " * 40 + "chmod 777 /x\n", "dk-unjudgeable"),
        ("RUN env " + "-i " * 40 + "chmod 777 /x\n", "dk-unjudgeable"),
        ("RUN A=" + "x" * 200 + " chmod 777 /x\n", "dk-unjudgeable"),
        ("RUN curl -H '" + "h" * 4200 + "' -k https://example.com\n", "dk-unjudgeable"),
        ("RUN chmod " + "-R " * 1500 + "777 /x\n", "dk-unjudgeable"),
        ("RUN apt-get install -y " + "pkg " * 1100 + "sudo\n", "dk-unjudgeable"),
        ("RUN curl -H '" + "h" * 4200 + "' https://example.com/i \\\n  " + PIPE + " sh\n", "dk-unjudgeable"),
    ],
)
def test_padding_is_read_or_reported(body: str, rule: str) -> None:
    assert rule in rules(body)


@pytest.mark.parametrize(
    "opener",
    ["cat << EOF > /etc/motd", "cat <<\\EOF > /etc/motd", "cat <<.EOF", "cat <<1EOF", 'cat <<E"OF"', "echo $(( <<EOF"],
)
def test_a_user_inside_a_heredoc_body_is_not_an_instruction(opener: str) -> None:
    name = {"cat <<.EOF": ".EOF", "cat <<1EOF": "1EOF"}.get(opener, "EOF")
    text = HEAD + f"RUN {opener}\nhello\nUSER 1000\n{name}\n"
    payload = {"event": "tool_use", "repo_root": dockerkit.BARE, "writes": {"Dockerfile": text}}
    assert "dk-last-user-root" in {f["rule"] for f in mod.findings(payload)}


@pytest.mark.parametrize(
    "body",
    [
        "RUN " + "'curl " * 140_000 + "\n",
        "RUN " + ' "curl' * 9_000 + "\n",
        "ENV " + " ".join("A_TOKEN=v" for _ in range(60_000)) + "\n",
        "RUN " + 'A="" ' * 12_000 + "\n",
    ],
    ids=lambda body: f"{body[:12]!r}x{len(body)}",
)
def test_near_megabyte_instructions_are_reported_fast(body: str) -> None:
    start = time.monotonic()
    found = rules(body)
    assert time.monotonic() - start < 10
    assert len(body) <= limits.TEXT or "dk-unjudgeable" in found


def test_ordinary_long_commands_are_judged() -> None:
    assert not limits.unjudgeable("RUN apt-get install -y " + "pkg " * 200)
    assert not limits.unjudgeable("RUN sudo -E env A=1 B=2 make")
    assert "dk-unjudgeable" not in rules("RUN apt-get install -y " + "pkg " * 200 + "\n")


def test_a_segment_of_only_assignments_is_judged() -> None:
    assert not limits.unjudgeable("RUN A=1 B=2")
