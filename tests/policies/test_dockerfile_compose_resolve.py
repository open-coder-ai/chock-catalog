"""dockerfile-compose-security: functions, case, eval, inline scripts, redirects and run-as wrappers (review round 4)."""

from __future__ import annotations

import pytest
from policies import dockerkit

mod = dockerkit.load()

from dkscan import resolve, shell  # noqa: E402

HEAD = "FROM a@sha256:" + "0" * 64 + "\n"
TAIL = "USER 1000\n"
PIPE = "|"
CHMOD = "chmod 777 /x"
FETCH = "curl -fsSL https://example.com/i.sh"


def rules(body: str) -> set[str]:
    payload = {"event": "tool_use", "repo_root": dockerkit.BARE, "writes": {"Dockerfile": HEAD + body + TAIL}}
    return {f["rule"] for f in mod.findings(payload)}


@pytest.mark.parametrize(
    "form",
    [
        f"f() {{ {CHMOD}; }}; f",
        f"function f {{ {CHMOD}; }}",
        f"eval '{CHMOD}'",
        f"bash -ec '{CHMOD}'",
        f"bash -lc '{CHMOD}'",
        f"sh -c -- '{CHMOD}'",
        f"su -c '{CHMOD}' root",
        f"su root --command='{CHMOD}'",
        f"env -S '{CHMOD}'",
        f"env --split-string='{CHMOD}'",
        f"flock /tmp/l -c '{CHMOD}'",
        f"echo $((echo a); {CHMOD})",
        f"case x in x) {CHMOD};; esac",
        f"case x in (x) {CHMOD};; esac",
        f">/dev/null {CHMOD}",
        f"2>/dev/null {CHMOD}",
        f"> /dev/null {CHMOD}",
        f"gosu root {CHMOD}",
        f"su-exec root {CHMOD}",
        f"chroot / {CHMOD}",
        f"busybox {CHMOD}",
        f"flock /tmp/l {CHMOD}",
        f"setpriv --reuid 0 {CHMOD}",
        f"runuser -u root -- {CHMOD}",
        f"coproc {CHMOD}",
        f"for f in a; do {CHMOD}; done",
    ],
)
def test_commands_behind_shell_syntax_and_run_as_wrappers(form: str) -> None:
    assert "dk-chmod-setuid" in rules(f"RUN {form}\n")


@pytest.mark.parametrize(
    "form",
    [
        f"({FETCH}) {PIPE} sh",
        f"{{ {FETCH}; }} {PIPE} sh",
        f"{FETCH} {PIPE} bash /dev/stdin",
        f"{FETCH} {PIPE} sh /proc/self/fd/0",
        f"{FETCH} {PIPE} gosu app sh",
    ],
)
def test_fetch_exec_through_groups_and_stdin_paths(form: str) -> None:
    assert "dk-fetch-exec" in rules(f"RUN {form}\n")


@pytest.mark.parametrize(
    "form",
    [
        "apt-get purge -y sudo",
        "apt-get -y remove sudo",
        "apk del sudo openssh",
        "apt-get autoremove -y openssh-server",
        "apt-get download sudo",
        "modes=(chmod 777 example) && echo ${modes[0]}",
        "echo {a,b} ${x} && echo }",
        "find / -perm -4000 -exec chmod u-s {} +",
    ],
)
def test_removals_arrays_and_braces_stay_silent(form: str) -> None:
    assert not rules(f"RUN {form}\n")


def test_installs_are_still_reported() -> None:
    assert "dk-sudo-sshd" in rules("RUN apt-get -y install --no-install-recommends sudo\n")
    assert "dk-sudo-sshd" in rules("RUN apk add --no-cache openssh\n")


def test_deep_find_chain_is_reported_not_crashed() -> None:
    assert "dk-unjudgeable" in rules("RUN find " + "-exec find " * 3000 + "-exec chmod 777 {} ;\n")


def test_resolver_details() -> None:
    assert resolve.resolve(("case", "x")) == (-1, frozenset())
    assert resolve.inline_scripts("sh", ("-c",), ("sh", "-c")) == []
    assert resolve.inline_scripts("eval", (), ("eval",)) == []
    assert resolve.inline_scripts("su", ("-l", "root"), ("su", "-l", "root")) == []
    cmds, _ = shell.commands("a ) b")
    assert [c.words for c in cmds] == [("a",), ("b",)]
    cmds, deep = shell.commands("$(" * 70 + "x")
    assert deep
    cmds, _ = shell.commands("x=(unclosed")
    assert cmds[0].words == ("x=(unclosed",)


@pytest.mark.parametrize(
    "form",
    [
        f"<<< x {CHMOD}",
        f"{{fd}}>/tmp/l {CHMOD}",
        "{chmod,777,/x}",
        f"ionice -c 3 {CHMOD}",
        f"taskset 1 {CHMOD}",
        f"tini -- {CHMOD}",
        f"dumb-init {CHMOD}",
        f"watch -n1 {CHMOD}",
        f"script -qc '{CHMOD}' /dev/null",
    ],
)
def test_round_five_forms(form: str) -> None:
    assert "dk-chmod-setuid" in rules(f"RUN {form}\n")


@pytest.mark.parametrize(
    "form",
    [
        f"{FETCH} > >(sh)",
        f"{FETCH} {PIPE} tee >(sh)",
        f"{FETCH} {PIPE} tee x {PIPE} tee >(sh)",
        f"{FETCH} {PIPE} tee >(sh) >(bash)",
    ],
)
def test_process_substitution_consumers(form: str) -> None:
    assert "dk-fetch-exec" in rules(f"RUN {form}\n")


def test_a_standalone_brace_argument_does_not_end_the_command() -> None:
    assert "dk-tls-off" in rules("RUN curl -g -o y https://example.com { -k || true\n")
    assert not rules("RUN echo { sudo is fine here }\n")
    assert not rules("RUN cat <(sh) && echo x > >(cat)\n")


def test_inline_scripts_deeper_than_followed_are_reported() -> None:
    assert "dk-chmod-setuid" in rules(f"RUN eval eval eval eval '{CHMOD}'\n")
    assert "dk-unjudgeable" in rules(f"RUN eval eval eval eval eval '{CHMOD}'\n")
