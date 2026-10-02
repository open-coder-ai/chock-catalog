"""Tools that run a command line handed to them: ssh, su -c, docker/kubectl exec, watch, chroot."""

import shlex

from chock_shellparse import Cmd


def runner_inner(cmd: Cmd) -> str | None:
    """The command line another tool runs for us (ssh, su -c, docker/kubectl exec, watch, chroot), or None."""
    name, args = cmd.name, cmd.args
    if name == "ssh":
        found = _after_values(
            args,
            frozenset(
                [
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
                ]
            ),
        )
        return " ".join(found[1:]) if found else None
    if name in ("su", "runuser", "script", "flock"):
        body = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-c", "--command") or a.startswith("--command=")]
        return body[0] if body else ("" if name in ("su", "runuser") else None)
    if name in ("docker", "podman", "nerdctl") and args[:1] in (["exec"], ["run"]):
        found = _after_values(args[1:], frozenset(), switches=_CONTAINER_SWITCHES)
        return shlex.join(found[1:]) if found else None
    if name in ("kubectl", "oc") and "exec" in args and "--" in args:
        return shlex.join(args[args.index("--") + 1 :])
    if name in ("watch", "chroot"):
        found = _after_values(args, frozenset(("-n", "--interval", "--userspec", "--groups")))
        return shlex.join(found[1:] if name == "chroot" else found) if found else None
    return None


_CONTAINER_SWITCHES = frozenset(
    [
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
    ]
)


def _after_values(args: list[str], values: frozenset[str], switches: frozenset[str] | None = None) -> list[str]:
    """The arguments from the first operand on, skipping each option's value (all options take one if `switches`)."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        takes = (args[i] not in switches and "=" not in args[i]) if switches is not None else args[i] in values
        i += 2 if takes else 1
    return args[i:]
