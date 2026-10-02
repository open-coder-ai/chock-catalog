"""Commands that run another command or a script (su -c, flock, strace, trap, fish -c ...), and a command nested too deep (stdlib only)."""

from __future__ import annotations

import shlex
from typing import Any, NamedTuple

from chock_shellparse import commands
from chock_shellparse.parse import _ASSIGN, _WRAPPERS, Cmd, _base, _crude, _inner, _Scan, _strip
from pathtext import scan

_LEVELS = 8
_SHORT = 2


class _Spec(NamedTuple):
    valued: frozenset[str]  # options that take a value, as written: -o --output
    plain: frozenset[str]  # options known to take none; "*" stands for every other short letter
    script: frozenset[str]  # options whose value is a script to run
    skip: int  # words before the command (flock: the lock file; chrt: the priority)
    argv: bool  # whether what follows is a command (su and the shells run their -c script only)
    joined: bool  # whether the shell joins the command words and parses them again (watch)


def _spec(valued: str = "", plain: str = "", script: str = "", **how: Any) -> _Spec:
    """A wrapper's options as sets of words; `how` sets skip, argv and joined."""
    words = (frozenset(text.split()) for text in (valued, plain, script))
    return _Spec(*words, how.get("skip", 0), how.get("argv", True), how.get("joined", False))


_SHELL = _spec("-o -O --rcfile --init-file", "*", "-c --command", argv=False)
WRAPPERS = {
    "su": _spec(
        "-s -g -G -w --shell --group --supp-group", "-l -m -p -P -f --login --fast", "-c --command", argv=False
    ),
    "fakeroot": _spec("-l -f -i -s -b --lib --faked", "-u -h -v -d --unknown-is-real"),
    "unshare": _spec(
        "-R -w -S -G --root --wd --setuid --setgid --propagation --setgroups --map-user --map-group --boottime"
        " --monotonic --map-users --map-groups",
        "-m -u -i -n -p -U -C -T -r -f -c --mount --uts --ipc --net --pid --user --cgroup --time --fork"
        " --map-root-user --map-auto --kill-child --mount-proc --keep-caps --map-current-user",
    ),
    "flock": _spec(
        "-w -E --timeout --conflict-exit-code",
        "-s -x -e -n -u -o -F -v --shared --exclusive --nonblock --nb --unlock --close --no-fork --verbose",
        "-c --command",
        skip=1,
    ),
    "taskset": _spec("", "-a -c -p --all-tasks --cpu-list --pid", skip=1),
    "chrt": _spec(
        "-T -P -D --sched-runtime --sched-deadline --sched-period",
        "-b -f -i -o -r -d -R -m -v -a -p --batch --fifo --idle --other --rr --deadline --reset-on-fork --max"
        " --verbose --all-tasks --pid",
        skip=1,
    ),
    "strace": _spec(
        "-a -b -e -E -I -o -O -p -P -s -S -u -U -X --output --env --signal --trace --inject --fault --read --write"
        " --attach --columns --string-limit --summary-sort-by --user --username",
        "-c -C -d -D -f -F -h -i -k -n -q -r -t -T -v -V -w -x -y -Y -z -Z -A",
    ),
    "ltrace": _spec("-a -A -e -F -l -n -o -p -s -u -w -x -D", "-b -c -C -d -f -h -i -L -r -S -t -T -V"),
    "watch": _spec(
        "-n --interval",
        "-b -c -d -e -f -g -h -p -q -t -v -w -x -B --beep --color --differences --errexit"
        " --exec --precise --no-title --no-wrap",
        joined=True,
    ),
    "unbuffer": _spec("", "-p"),
    "chronic": _spec("", "*"),
    "tsp": _spec("-L -N -D -S", "*"),
    "busybox": _spec(),
    "nsenter": _spec("-t -S -G -w -r --target --setuid --setgid --wd --root", "-m -u -i -n -p -C -T -U -a -F -Z"),
    "setpriv": _spec(
        "--reuid --regid --groups --inh-caps --ambient-caps --bounding-set --securebits --pdeathsig --selinux-label"
        " --apparmor-profile --ruid --euid --rgid --egid",
        "--init-groups --clear-groups --keep-groups --no-new-privs --dump --reset-env",
    ),
    "chroot": _spec("--userspec --groups", "--skip-chdir", skip=1),
    **dict.fromkeys(("fish", "csh", "tcsh", "mksh", "rbash", "yash", "xonsh", "nu", "nushell", "elvish"), _SHELL),
}
WRAP = frozenset((*WRAPPERS, "trap", "coproc"))


def _option(spec: _Spec, arg: str, following: str | None) -> tuple[bool, str | None, bool]:
    """(whether the next word is this option's value, a script value, whether the option is unknown)."""
    if arg.startswith("--"):
        name, equals, value = arg.partition("=")
        if name in spec.script:
            return not equals, value if equals else following, False
        return (name in spec.valued and not equals), None, name not in spec.valued | spec.plain
    for at, char in enumerate(arg[1:], 1):
        flag, tail = f"-{char}", arg[at + 1 :]
        if flag in spec.script:
            return not tail, tail or following, False
        if flag in spec.valued:
            return not tail, None, False
        if flag not in spec.plain and "*" not in spec.plain:
            return False, None, True
    return False, None, False


def unwrap(name: str, args: list[str]) -> tuple[list[str], bool] | None:
    """The scripts a wrapper runs and whether an option it does not know leaves the command position unsure; None if it is no wrapper."""
    if name == "coproc":
        return [" ".join(args)], False
    if name == "trap":
        rest = args[1:] if args[:1] == ["--"] else args
        return ([rest[0]] if rest and rest[0] not in ("-", "-l", "-p") else []), False
    spec = WRAPPERS.get(name)
    if spec is None:
        return None
    scripts, unsure, at, seen, done = [], False, 0, 0, False
    while at < len(args):
        arg, at = args[at], at + 1
        if not done and arg == "--":
            done = True
        elif not done and arg.startswith("-") and len(arg) > 1:
            took, script, odd = _option(spec, arg, args[at] if at < len(args) else None)
            at += took
            unsure |= odd
            scripts += [script] if script is not None else []
        elif not spec.argv:
            continue
        elif seen < spec.skip:
            seen += 1
        else:
            at -= 1
            break
    rest = args[at:] if spec.argv and not scripts else []
    if rest:
        scripts.append(" ".join(rest) if spec.joined else shlex.join(rest))
    return scripts, unsure


def nested(cmd: Cmd) -> bool:
    """Whether a command is a shell's script that the reader left unread: `bash -c` nested past its depth limit."""
    script = _inner(cmd.name, cmd.args)
    return script is not None and script.strip() != ""


def too_deep(text: str, level: int = 0) -> bool:
    """Whether a command line holds a script nested past what the shared reader unwraps, or past `_LEVELS`."""
    if level > _LEVELS:
        return True
    scanned = scan(text)
    return any(nested(c) for c in commands(scanned.outer)) or any(too_deep(b, level + 1) for b in scanned.bodies)


def env_scripts(text: str, level: int = 0) -> list[str]:
    """The strings given to `env -S`, which the shared reader takes for an option value and drops."""
    found: list[str] = []
    for clause in _Scan(text).run() or _crude(text):
        words = list(clause.words)
        while words and (_ASSIGN.match(words[0]) or (_base(words[0]) in _WRAPPERS and _base(words[0]) != "env")):
            words = words[1:] if _ASSIGN.match(words[0]) else _strip(_base(words[0]), words[1:])
        if not words:
            continue
        name = _base(words[0])
        script = _inner(name, words[1:])
        if script is not None and level < _LEVELS:
            found += env_scripts(script, level + 1)
        elif name == "env":
            found += _split(words[1:])
    return found


def _split(words: list[str]) -> list[str]:
    """The `env -S` string, with the words after it, from the options of an env command."""
    at = 0
    while at < len(words):
        word = words[at]
        tail = [*map(shlex.quote, words[at + 1 :])]
        if word in ("-S", "--split-string") and at + 1 < len(words):
            return [" ".join([words[at + 1], *map(shlex.quote, words[at + 2 :])])]
        if word.startswith("--split-string="):
            return [" ".join([word.partition("=")[2], *tail])]
        if word.startswith("-S") and len(word) > _SHORT:
            return [" ".join([word[2:], *tail])]
        if word in ("-u", "-C", "--unset", "--chdir"):
            at += 1
        elif not word.startswith("-") and "=" not in word:
            break
        at += 1
    return []
