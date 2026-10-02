#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse the shell commands that publish, expose or keep access after the session: package and image publishes,
# user services, scheduled jobs, Run keys, ssh login keys, CI runner registration, sudoers, setuid bits, detached downloads.
# Best effort: the command is read as text, so a script file, an alias or a program it builds at run time is out of reach.

import os
import re
import shlex
import sys

import shapes_background
import shapes_data
import shapes_paths
import shapes_rules
from chock_shellparse import Cmd, commands, git_parts, positionals, writes_files

BLOCK, ASK = 1, 3
LEVELS = {"block": BLOCK, "ask": ASK}
Verdict = tuple[int, str]
PUSH_VALUE = frozenset(("--repo", "-o", "--push-option", "--receive-pack", "--exec"))
OUTPUT_FLAGS = {"curl": ("-o", "--output"), "wget": ("-O", "--output-document", "-P", "--directory-prefix")}
TAILS = {
    BLOCK: "Publishing, persistence and visibility changes are human decisions: ask the person to run it from their own shell.",
    ASK: "Ask the person to confirm before it runs.",
}


def git_verdict(cmd: Cmd, tab: dict) -> Verdict | None:
    """`git remote add|set-url`, and `git push` to an explicit URL or through a URL override, are asked about."""
    if cmd.name != "git":
        return None
    sub, conf, rest = git_parts(cmd.args)
    if sub not in ("push", "remote"):
        return None
    if any(re.search(r"url|insteadof", entry.split("=", 1)[0], re.IGNORECASE) for entry in conf):
        return ASK, f"git {sub} with a URL override in -c reaches a host the person has not approved."
    if sub == "remote":
        word = (positionals(rest, frozenset()) or [""])[0]
        return (
            (ASK, f"git remote {word} points the repository at another host.") if word in ("add", "set-url") else None
        )
    target = [*positionals(rest, PUSH_VALUE)[:1], shapes_rules.value_of(rest, "--repo")]
    if any(re.search(tab["url_arg"], word) for word in target):
        return (
            ASK,
            "git push to an explicit URL sends the history to a host the person has not approved; push to a named remote.",
        )
    return None


def setid_verdict(cmd: Cmd, tab: dict) -> Verdict | None:
    """chmod or install -m with a setuid or setgid bit plants a privilege-escalation file."""
    if cmd.name == "chmod":
        modes = cmd.args
    elif cmd.name == "install":
        modes = [shapes_rules.value_of(cmd.args, "-m", "--mode")]
    else:
        return None
    for mode in modes:
        if re.search(tab["setid_numeric"], mode) or any(
            re.search(tab["setid_symbolic"], part) for part in mode.split(",")
        ):
            return BLOCK, f"{cmd.name} {mode} sets a setuid or setgid bit, a file that runs with another user's rights."
    return None


def write_verdict(cmd: Cmd, tab: dict, *, hot: bool) -> Verdict | None:
    """A write to a startup, scheduler, sudoers or ssh login location; `hot` is a working directory in one."""
    hit = shapes_paths.hits(tab, hot=hot)
    saved = [value for flag in OUTPUT_FLAGS.get(cmd.name, ()) if (value := shapes_rules.value_of(cmd.args, flag))]
    exempt = cmd.name in tab["write_exempt"]
    if any(hit(path) for path in [*cmd.writes, *saved]) or (not exempt and writes_files(cmd, hit)):
        return (
            BLOCK,
            "writing to a service, launch agent, scheduler, sudoers or ssh login-key location keeps access after the session.",
        )
    return None


def verdicts(cmd: Cmd, tab: dict, *, hot: bool) -> list[Verdict]:
    ruled = shapes_rules.judge(cmd, tab)
    first = [(LEVELS[ruled[0]], ruled[1])] if ruled else []
    return [*first, *filter(None, (git_verdict(cmd, tab), setid_verdict(cmd, tab), write_verdict(cmd, tab, hot=hot)))]


def check(raw: str) -> Verdict | None:
    """The strictest verdict for a command line (block over ask), or None; the reason names the compliant way."""
    tab = shapes_data.table()
    found: list[Verdict] = []
    named = [name for name in tab["iocs"] if name in raw.lower()]
    found += [(BLOCK, f"{name} is the name of a known token-stealing persistence implant.") for name in named]
    hot = False
    for cmd in commands(raw):
        hot = shapes_paths.enters(cmd, tab, hot=hot)
        found += verdicts(cmd, tab, hot=hot)
    started = shapes_background.detached(raw, tab)
    if started:
        found.append(
            (
                BLOCK,
                f"{started} detached with & or nohup/setsid keeps running after the session; run it in the foreground.",
            )
        )
    found.sort(key=lambda item: item[0] != BLOCK)
    return (found[0][0], f"{found[0][1].rstrip('.')}. {TAILS[found[0][0]]}") if found else None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        verdict = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-persistence-shapes: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if verdict:
        print(f"{'BLOCKED' if verdict[0] == BLOCK else 'ASK'}: {verdict[1]}", file=sys.stderr)
    return verdict[0] if verdict else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
