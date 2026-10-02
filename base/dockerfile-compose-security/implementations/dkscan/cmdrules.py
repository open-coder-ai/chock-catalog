"""Rules over resolved commands: the program after wrappers and assignments, and its words.

Each rule yields (rule id, offset, why); the caller places the offset on its physical line.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator

from dkscan.shell import Cmd, resolve

FETCHERS = frozenset(
    {"curl", "wget", "wget2", "aria2c", "lynx", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"}
)
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "csh", "tcsh", "mksh", "fish", "busybox"})
SCRIPTERS = frozenset({"python", "perl", "ruby", "node", "php", "lua", "deno", "bun", "pwsh", "powershell"})
EVALUATORS = frozenset({"eval", "source", ".", "iex", "invoke-expression"})
#: Options that make an interpreter run inline code instead of reading its script from stdin.
INLINE = frozenset({"-c", "-e", "-E", "-m", "-r", "-p", "-Command", "-command", "-EncodedCommand"})
PACKAGERS = frozenset({"apt-get", "apt", "apk", "yum", "dnf", "microdnf", "tdnf", "zypper"})
SSH_PACKAGES = frozenset({"sudo", "openssh", "openssh-server"})
RPM_NO_CHECK = frozenset({"--nodigest", "--nosignature", "--noverify", "--nofiledigest"})
USER_TOOLS = frozenset({"useradd", "adduser", "usermod"})
GIT_VALUE_OPTIONS = frozenset({"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"})
GIT_PINS = frozenset({"checkout", "switch", "reset", "fetch"})
SHA = re.compile(r"[0-9a-fA-F]{40}")
CURL_INSECURE = re.compile(r"-[A-Za-z0-9]*k[A-Za-z0-9]*")
NUMERIC = re.compile(r"[0-7]{3,5}")
SYMBOLIC = re.compile(r"([ugoa]*)([-+=])([rwxXst]*)")
PERMS, STICKY = 3, 1


def name(word: str) -> str:
    base = posixpath.basename(word)
    lowered = base.lower()
    if lowered in FETCHERS or lowered in EVALUATORS or lowered in ("pwsh", "powershell"):
        return lowered
    return re.sub(r"[0-9.]+$", "", base) if base.startswith("python") else base


def program(cmd: Cmd) -> tuple[str, tuple[str, ...], frozenset[str]]:
    """(program name, its arguments, wrappers before it); name "" when only wrappers are left."""
    at, wrappers = resolve(cmd.words)
    if at < 0:
        return "", (), wrappers
    return name(cmd.words[at]), cmd.words[at + 1 :], wrappers


def _numeric(mode: str) -> str:
    special = int(mode[:-PERMS] or "0", 8)
    if special & 0o6:
        return "sets the setuid or setgid bit"
    if int(mode[-1]) & 0o2 and not special & STICKY:
        return "makes the file world-writable"
    return ""


def mode_why(mode: str) -> str:
    """Why a numeric or symbolic file mode is too broad, or ""."""
    if NUMERIC.fullmatch(mode):
        return _numeric(mode)
    for who, op, perms in SYMBOLIC.findall(mode):
        if op != "-" and "s" in perms:
            return "sets the setuid or setgid bit"
        if op != "-" and "w" in perms and ("a" in who or "o" in who):
            return "makes the file world-writable"
    return ""


def chmod_why(args: tuple[str, ...]) -> str:
    for arg in args:
        if arg.startswith("-") and not SYMBOLIC.fullmatch(arg):
            continue
        return mode_why(arg)
    return ""


def install_why(args: tuple[str, ...]) -> str:
    for at, arg in enumerate(args):
        if arg == "-m" and at + 1 < len(args):
            return mode_why(args[at + 1])
        if arg.startswith(("--mode=", "-m")) and len(arg) > 2:  # noqa: PLR2004
            return mode_why(arg.split("=", 1)[-1] if "=" in arg else arg[2:])
    return ""


def reads_stdin(args: tuple[str, ...]) -> bool:
    """Whether an interpreter given these arguments runs what arrives on stdin."""
    for arg in args:
        if arg in ("-", "-s", "--"):
            return True
        if arg in INLINE:
            return False
        if not arg.startswith("-"):
            return False
    return True


def find_exec(args: tuple[str, ...]) -> Iterator[tuple[str, ...]]:
    """The commands find runs with -exec, -execdir, -ok or -okdir."""
    at = 0
    while at < len(args):
        if args[at] in ("-exec", "-execdir", "-ok", "-okdir"):
            end = at + 1
            while end < len(args) and args[end] not in (";", "+"):
                end += 1
            yield args[at + 1 : end]
            at = end
        at += 1


def git_subcommand(args: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    at = 0
    while at < len(args) and args[at].startswith("-"):
        at += 2 if args[at] in GIT_VALUE_OPTIONS else 1
    return (args[at], args[at + 1 :]) if at < len(args) else ("", ())


def simple(prog: str, args: tuple[str, ...], wrappers: frozenset[str]) -> Iterator[tuple[str, str]]:
    """Findings one command shows on its own: (rule id, why)."""
    if "sudo" in wrappers:
        yield "dk-sudo-sshd", "sudo in the image"
    if prog == "curl" and any(a == "--insecure" or CURL_INSECURE.fullmatch(a) for a in args):
        yield "dk-tls-off", "curl with certificate checks off"
    if "insecure" in args and any(a.endswith(".curlrc") for a in args):
        yield "dk-tls-off", "insecure written to a .curlrc"
    if prog == "rpm" and RPM_NO_CHECK & set(args):
        yield "dk-signature-bypass", "rpm with signature checks off"
    if prog in PACKAGERS and args[:1] != ("remove",) and SSH_PACKAGES & set(args):
        yield "dk-sudo-sshd", "sudo or an SSH server installed in the image"
    if prog == "chpasswd" or (prog == "passwd" and {"-d", "--delete", "--stdin"} & set(args)):
        yield "dk-chpasswd", "a password set or removed in the image"
    if prog in USER_TOOLS and any(a == "-p" or a.startswith("--password=") or a == "--password" for a in args):
        yield "dk-chpasswd", "a password set in the image"
    yield from _modes(prog, args)


def _modes(prog: str, args: tuple[str, ...]) -> Iterator[tuple[str, str]]:
    """chmod, install -m, and the commands find -exec runs."""
    why = chmod_why(args) if prog == "chmod" else install_why(args) if prog == "install" else ""
    if why:
        yield "dk-chmod-setuid", f"mode {why}"
    if prog == "find":
        for sub in find_exec(args):
            if sub:
                yield from simple(name(sub[0]), sub[1:], frozenset())


def fetch_exec(cmds: list[Cmd]) -> Iterator[tuple[Cmd, Cmd]]:
    """(fetch, runner) pairs: a download piped (through any stages) or substituted into an interpreter.

    Commands come out in the order they end, so a pipe's upstream stage and a substitution's inner
    command are seen before the command that uses them: one pass, linear in the number of commands.
    """
    by_id = {cmd.id: cmd for cmd in cmds}
    fetch_up: dict[int, int] = {}
    fetched_into: dict[int, int] = {}
    for cmd in cmds:
        prog, args, _ = program(cmd)
        if prog in FETCHERS:
            fetched_into.setdefault(cmd.parent, cmd.id)
        upstream = by_id.get(cmd.piped_from)
        if upstream is not None:
            fetch_up[cmd.id] = upstream.id if program(upstream)[0] in FETCHERS else fetch_up.get(upstream.id, 0)
        if "\x00" in prog and cmd.id in fetched_into:
            yield by_id[fetched_into[cmd.id]], cmd
            continue
        if not (prog in SHELLS or prog in SCRIPTERS or prog in EVALUATORS):
            continue
        source = fetch_up.get(cmd.id, 0) if reads_stdin(args) else 0
        source = source or fetched_into.get(cmd.id, 0)
        if source:
            yield by_id[source], cmd


def clones(cmds: list[Cmd]) -> Iterator[Cmd]:
    """git clone commands with no later checkout, switch, reset or fetch of a 40-hex commit."""
    pins = []
    found = []
    for cmd in cmds:
        prog, args, _ = program(cmd)
        sub, rest = git_subcommand(args) if prog == "git" else ("", ())
        if sub == "clone":
            found.append(cmd)
            if any(SHA.fullmatch(a.removeprefix("--revision=")) for a in rest):
                pins.append(cmd.start)
        elif sub in GIT_PINS and any(SHA.fullmatch(a) for a in rest):
            pins.append(cmd.start)
    last = max(pins, default=-1)
    for cmd in found:
        if last < cmd.start:
            yield cmd
