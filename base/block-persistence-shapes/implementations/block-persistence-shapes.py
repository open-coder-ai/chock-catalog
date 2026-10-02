#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse the shell commands that publish, expose or keep access after the session: package and image publishes,
# user services, scheduled jobs, Run keys, ssh login keys, CI runner registration, sudoers, setuid bits, detached downloads.
# Best effort: the command is read as text, so a script file, an alias or a program it builds at run time is out of reach.

import os
import posixpath
import re
import shlex
import sys
import threading

import shapes_background
import shapes_data
import shapes_paths
import shapes_rules
from chock_shellparse import Cmd, commands, git_parts, operands, positionals, writes_files

BLOCK, ASK = 1, 3
LEVELS = {"block": BLOCK, "ask": ASK}
Verdict = tuple[int, str]
PUSH_VALUE = frozenset(("--repo", "-o", "--push-option", "--receive-pack", "--exec"))
BUDGET = 5.0
GIT_CONFIG_READS = frozenset(
    ("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "--unset", "--unset-all")
)
INTO_FOLDER = frozenset(("cp", "mv", "install", "ln"))
OUTPUT_FLAGS = {
    "curl": ("-o", "--output", "--output-dir"),
    "wget": ("-O", "--output-document", "-P", "--directory-prefix"),
}
TIMEOUT = "The command line is too long or too tangled to check in time; split it into shorter commands, or ask the person to run it."
TAILS = {
    BLOCK: "Publishing, persistence and visibility changes are human decisions: ask the person to run it from their own shell.",
    ASK: "Ask the person to confirm before it runs.",
}


def git_verdict(cmd: Cmd, tab: dict) -> Verdict | None:
    """`git remote add|set-url`, and `git push` to an explicit URL or through a URL override, are asked about."""
    sub, conf, rest = git_parts(cmd.args) if cmd.name == "git" else ("", [], [])
    if sub == "config":
        return config_verdict(rest, tab)
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


def config_verdict(rest: list[str], tab: dict) -> Verdict | None:
    """`git config remote.<n>.url|pushurl` or `url.<base>.insteadOf` set to a value re-points a later push."""
    words = positionals(rest, frozenset(("--file", "-f", "--blob")))
    if len(words) > 1 and not GIT_CONFIG_READS & set(rest) and re.search(tab["git_url_key"], words[0], re.IGNORECASE):
        return ASK, f"git config {words[0]} points later pushes at another host."
    return None


def install_modes(args: list[str]) -> list[str]:
    """The modes of `install -m 4755`, `-m4755`, `-Dm4755` and `--mode=u+s`."""
    found = []
    for i, arg in enumerate(args):
        match = re.fullmatch(r"(?:-[A-Za-z]*m|--mode)(?:=?(.+))?", arg)
        if match:
            found.append(match.group(1) or (args[i + 1] if i + 1 < len(args) else ""))
    return found


def setid_verdict(cmd: Cmd, tab: dict) -> Verdict | None:
    """chmod or install -m with a setuid or setgid bit plants a privilege-escalation file."""
    if cmd.name == "chmod":
        modes = operands(cmd.args)[:1]
    elif cmd.name == "install":
        modes = install_modes(cmd.args)
    else:
        return None
    for mode in modes:
        if re.search(tab["setid_numeric"], mode) or any(
            re.search(tab["setid_symbolic"], part) for part in mode.split(",")
        ):
            return BLOCK, f"{cmd.name} {mode} sets a setuid or setgid bit, a file that runs with another user's rights."
    return None


def clustered(args: list[str], letter: str) -> list[str]:
    """The values of a short option that may sit in a cluster: `-sSLo FILE`, `-qOFILE`."""
    found = []
    for i, arg in enumerate(args):
        match = re.fullmatch(rf"-[A-Za-z0-9]*{letter}(.*)", arg)
        if match:
            found.append(match.group(1) or (args[i + 1] if i + 1 < len(args) else ""))
    return found


def saved_paths(cmd: Cmd) -> list[str]:
    """Where curl and wget put the download: `-o`/`-O` alone, in a cluster or glued to the path, `--output`, `-P`."""
    found = []
    for flag in OUTPUT_FLAGS.get(cmd.name, ()):
        found.append(shapes_rules.value_of(cmd.args, flag))
        if not flag.startswith("--"):
            found += clustered(cmd.args, flag[1])
    return [path for path in found if path]


def folder_paths(cmd: Cmd) -> list[str]:
    """cp, mv, install, ln with `-t DIR` or `--target-directory DIR`: the folder, and each source named inside it."""
    if cmd.name not in INTO_FOLDER:
        return []
    folders = [*clustered(cmd.args, "t"), shapes_rules.value_of(cmd.args, "--target-directory")]
    sources = positionals(cmd.args, frozenset(("-t", "--target-directory")))
    return [
        path
        for folder in folders
        if folder
        for path in (folder, *(posixpath.join(folder, posixpath.basename(s)) for s in sources))
    ]


def write_verdict(cmd: Cmd, tab: dict, *, hot: bool) -> Verdict | None:
    """A write to a startup, scheduler, sudoers or ssh login location; `hot` is a working directory in one."""
    hit = shapes_paths.hits(tab, hot=hot)
    exempt = cmd.name in tab["write_exempt"]
    if any(hit(path) for path in [*cmd.writes, *saved_paths(cmd), *folder_paths(cmd)]) or (
        not exempt and writes_files(cmd, hit)
    ):
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


def bounded(raw: str, seconds: float) -> Verdict | None:
    """`check`, but a line the parser cannot read in `seconds` is refused (a hook timeout would let it through)."""
    box: list[tuple[Verdict | None, Exception | None]] = []

    def work() -> None:
        try:
            box.append((check(raw), None))
        except Exception as exc:  # noqa: BLE001 -- handed back to the caller, which reports the fault
            box.append((None, exc))

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(seconds)
    if not box:
        return BLOCK, TIMEOUT
    found, fault = box[0]
    if fault:
        raise fault
    return found


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        verdict = bounded(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv), BUDGET)
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-persistence-shapes: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if verdict:
        print(f"{'BLOCKED' if verdict[0] == BLOCK else 'ASK'}: {verdict[1]}", file=sys.stderr)
    return verdict[0] if verdict else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
