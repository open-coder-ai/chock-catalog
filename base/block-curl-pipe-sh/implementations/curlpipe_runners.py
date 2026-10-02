"""Tools that run a command line handed to them: ssh, su -c, docker/kubectl exec, watch, chroot, taskset and kin."""

import shlex

from chock_shellparse import Cmd

_SSH_VALUES = frozenset(
    (
        "-b",
        "-c",
        "-D",
        "-E",
        "-e",
        "-F",
        "-I",
        "-i",
        "-J",
        "-L",
        "-l",
        "-m",
        "-O",
        "-o",
        "-p",
        "-Q",
        "-R",
        "-S",
        "-W",
        "-w",
        "-B",
    )
)
_CONTAINER_SWITCHES = frozenset(
    (
        "-i",
        "-t",
        "-d",
        "-it",
        "-ti",
        "-id",
        "-dit",
        "-itd",
        "--rm",
        "--init",
        "--privileged",
        "--read-only",
        "-P",
        "--interactive",
        "--tty",
        "--detach",
    )
)
#: Wrappers chock_shellparse does not strip: (options that take a value, positionals before the command).
_ARGV_WRAPPERS = {
    "chrt": (frozenset(), 1),
    "taskset": (frozenset(("-c", "--cpu-list")), 1),
    "unbuffer": (frozenset(), 0),
    "nsenter": (frozenset(("-t", "--target", "-S", "--setuid", "-G", "--setgid")), 0),
    "unshare": (frozenset(), 0),
    "setpriv": (frozenset(), 0),
    "firejail": (frozenset(), 0),
    "prlimit": (frozenset(), 0),
    "cgexec": (frozenset(("-g",)), 0),
    "systemd-run": (frozenset(("-p", "--property", "-u", "--unit", "-E", "--setenv", "-M", "--machine")), 0),
    "chroot": (frozenset(("--userspec", "--groups")), 1),
}


def runner_inner(cmd: Cmd) -> str | None:  # noqa: PLR0911 -- one return per runner family reads plainer
    """The command line another tool runs for us, or None when the command is not such a runner."""
    name, args = cmd.name, cmd.args
    if name == "ssh":
        found = _after_values(args, _SSH_VALUES)
        return " ".join(found[1:]) if found else None
    if name in ("su", "runuser", "script", "flock"):
        body = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-c", "--command")]
        return body[0] if body else ("" if name in ("su", "runuser") else None)
    if name in ("docker", "podman", "nerdctl") and args[:1] in (["exec"], ["run"]):
        found = _after_values(args[1:], frozenset(), switches=_CONTAINER_SWITCHES)
        return shlex.join(found[1:]) if found else None
    if name in ("kubectl", "oc") and "exec" in args and "--" in args:
        return shlex.join(args[args.index("--") + 1 :])
    if name == "watch":
        return " ".join(_after_values(args, frozenset(("-n", "--interval"))))
    if name in _ARGV_WRAPPERS:
        values, skip = _ARGV_WRAPPERS[name]
        found = _after_values(args, values)
        skip = 0 if name == "taskset" and any(a in values for a in args) else skip
        return shlex.join(found[skip:])
    return None


def _after_values(args: list[str], values: frozenset[str], switches: frozenset[str] | None = None) -> list[str]:
    """The arguments from the first operand on, skipping each option's value (all options take one if `switches`)."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        takes = (args[i] not in switches and "=" not in args[i]) if switches is not None else args[i] in values
        i += 2 if takes else 1
    return args[i:]
