"""Host-path rows: removals, devices, permissions and lockouts. Skipped inside a container exec (shared byte for byte)."""

import posixpath
import re
from collections.abc import Callable
from itertools import takewhile

from chock_shellparse import (
    Cmd,
    abbreviates,
    flags_of,
    is_dangerous_target,
    operands,
    positionals,
    removes_root_recursively,
)

Hit = tuple[str, str] | None
_SYSTEM = "bin|boot|dev|etc|home|lib|lib32|lib64|opt|proc|root|sbin|srv|sys|usr|var"
_ROOT = re.compile(rf"/\*?|/({_SYSTEM})(/\*?)?|~([a-z_][\w.-]*)?/?\*?|\$\{{?HOME\}}?(/\*?)?", re.IGNORECASE)
_CWD = frozenset(("$PWD", "${PWD}", "$(pwd)", "~+"))
# rtk's safe list: build output a developer deletes all day, matched on the last path segment.
SAFE_DIRS = frozenset(
    (
        *("node_modules", "dist", "build", ".next", "__pycache__", ".cache", "tmp", ".tmp", "coverage"),
        *(".nyc_output", "target", ".turbo", ".parcel-cache"),
    )
)
_QUIET_DEVICES = re.compile(r"/dev/(null|zero|stdout|stderr|tty|fd/\d+)")
_KEYS = frozenset(("authorized_keys", "authorized_keys2"))
_CLOBBER = re.compile(r"(^|[^>])>\|?\s*[\"']?[^\s;&|<>]*authorized_keys2?([\s\"';&|)]|$)")
_COPIERS = frozenset(("cp", "mv", "install", "ln", "scp", "rsync"))
_ERASERS = frozenset(("rm", "unlink", "truncate", "shred"))
_SYSTEMCTL_VALUES = frozenset(("-H", "--host", "-M", "--machine", "-t", "--type", "-p", "--property", "-o", "--output"))
_EXEC_FLAGS = frozenset(("-exec", "-execdir", "-ok"))


def is_root(path: str) -> bool:
    """`/`, a top-level system directory, or home (also as a `/*` glob): never a routine target."""
    # Home is a stand-in no user name can spell while normalising; a path that climbs out of it (`~/..`,
    # `~/../etc`) reaches wherever home's parent is, which is unknown here, so it counts as a root.
    home = re.match(r"(~[a-z_][\w.-]*|~|\$\{?HOME\}?)(?=/|$)", path, re.IGNORECASE)
    if home:
        spot = posixpath.normpath("/home/~" + path[home.end() :])
        return spot in ("/home/~", "/home/~/*") or not spot.startswith("/home/~/")
    return _ROOT.fullmatch(re.sub("/+", "/", posixpath.normpath(path))) is not None


def is_cwd(path: str) -> bool:
    """The working directory or its parent, however it is spelled."""
    return path.rstrip("/") in _CWD or (path.strip("/") in (".", "..") and path.startswith("."))


def _safe(path: str) -> bool:
    return path.rstrip("/").rsplit("/", 1)[-1] in SAFE_DIRS


def has(cmd: Cmd, short: set[str], long: str) -> bool:
    """A short flag, or any prefix of three characters or more of the long one (getopt takes unambiguous prefixes;
    an ambiguous one fails to run anyway, so matching it only errs strict)."""
    flags = flags_of(cmd.args)
    return bool(flags & short) or any(abbreviates(f, long, len("--r")) for f in flags if f.startswith("--"))


def rm(cmd: Cmd) -> Hit:
    targets = operands(cmd.args)
    if not has(cmd, {"-r", "-R"}, "--recursive"):
        return None
    forced = has(cmd, {"-f"}, "--force")
    if forced and (hit := next((t for t in targets if is_dangerous_target(t) or is_cwd(t)), None)):
        return "rm-rf", hit
    if hit := next((t for t in targets if is_root(t)), None):
        return "rm-root", hit
    hit = next((t for t in targets if not _safe(t)), None) if forced else None
    return None if hit is None else ("rm-relative", hit)


def unlink(cmd: Cmd) -> Hit:
    hit = next((t for t in operands(cmd.args) if is_root(t)), None)
    return None if hit is None else ("unlink-root", f"{cmd.name} '{hit}'")


def mv(cmd: Cmd) -> Hit:
    """Only sources move: every operand but the last, or every operand when -t names the destination."""
    items, target = operands(cmd.args), next((a for a in cmd.args if a.startswith("--target-directory")), "")
    if "-t" in flags_of(cmd.args) or target:
        sources = positionals(cmd.args, frozenset(("-t", "--target-directory")))
    else:
        sources = items[:-1]
    hit = next((s for s in sources if is_root(s)), None)
    return None if hit is None else ("mv-root", hit)


def _changed(cmd: Cmd) -> list[str]:
    """chmod/chown/chgrp targets: every operand after the mode or owner, or all of them with --reference."""
    items = operands(cmd.args)
    return items if any(a.startswith("--reference") for a in cmd.args) else items[1:]


def chmod(cmd: Cmd) -> Hit:
    """Any recursive chmod of root, a system directory or home: no mode makes that routine."""
    hit = has(cmd, {"-R"}, "--recursive") and any(is_root(t) for t in _changed(cmd))
    return ("chmod-root", (operands(cmd.args) or [""])[0]) if hit else None


def chown(cmd: Cmd) -> Hit:
    hit = has(cmd, {"-R"}, "--recursive") and any(is_root(t) for t in _changed(cmd))
    return ("chown-root", cmd.name) if hit else None


def dd(cmd: Cmd) -> Hit:
    paths = [re.sub("/+", "/", posixpath.normpath(a[3:])) for a in cmd.args if a.startswith("of=")]
    hit = next((p for p in paths if p.startswith("/dev/") and not _QUIET_DEVICES.fullmatch(p)), None)
    return None if hit is None else ("dd-device", hit)


def mkfs(cmd: Cmd) -> Hit:
    asking = {"-h", "--help", "-V", "--version"} & set(cmd.args)
    return None if asking else ("mkfs", cmd.name)


def find(cmd: Cmd) -> Hit:
    args = cmd.args
    if not ("-delete" in args or (_EXEC_FLAGS & set(args) and "rm" in args)):
        return None
    roots = list(takewhile(lambda arg: not arg.startswith(("-", "(", "!")), args))
    hit = next((r for r in roots or ["."] if is_dangerous_target(r)), None)
    return None if hit is None else ("find-delete", hit)


def shred(cmd: Cmd) -> Hit:
    hit = next((t for t in operands(cmd.args) if is_dangerous_target(t)), None)
    return None if hit is None else ("shred", f"{cmd.name} targeting '{hit}'")


def wipefs(cmd: Cmd) -> Hit:
    return ("wipefs", "") if flags_of(cmd.args) & {"-a", "--all", "-o", "--offset"} else None


def powershell_remove(cmd: Cmd) -> Hit:
    return ("powershell-remove", "") if removes_root_recursively(cmd) else None


def keys(cmd: Cmd, raw: str) -> Hit:
    """authorized_keys clobbered by `>`, tee without -a, a copy onto it, or an rm/truncate/shred of it."""
    named = [p for p in (*cmd.writes, *operands(cmd.args)) if p.replace("\\", "/").rsplit("/", 1)[-1] in _KEYS]
    items = operands(cmd.args)
    clobbered = (
        (any(p in cmd.writes for p in named) and _CLOBBER.search(raw) is not None)
        or (cmd.name == "tee" and not flags_of(cmd.args) & {"-a", "--append"} and bool(named))
        or (cmd.name in _COPIERS and bool(items) and items[-1] in named)
        or (cmd.name in _ERASERS and bool(named))
    )
    return ("authorized-keys", named[0]) if clobbered else None


def usermod(cmd: Cmd) -> Hit:
    return ("account-lock", f"{cmd.name} -L") if has(cmd, {"-L"}, "--lock") else None


def passwd(cmd: Cmd) -> Hit:
    return ("account-lock", f"{cmd.name} -l") if has(cmd, {"-l"}, "--lock") else None


def chattr(cmd: Cmd) -> Hit:
    hit = next((a for a in cmd.args if a[:1] in "+=" and "i" in a), None)
    return None if hit is None else ("chattr-immutable", hit)


def kill(cmd: Cmd) -> Hit:
    """`kill -9 -1`, `kill -s KILL -1`, `kill -- -1`: -1 in the pid slot is every process; `kill -1 <pid>` is SIGHUP."""
    return ("kill-all", "") if "-1" in cmd.args[1:] else None


def pkill(cmd: Cmd) -> Hit:
    return ("kill-pattern", "pkill -f") if flags_of(cmd.args) & {"-f", "--full"} else None


def killall(cmd: Cmd) -> Hit:
    probing = "-0" in cmd.args
    return ("kill-pattern", cmd.name) if operands(cmd.args) and not probing else None


def crontab(cmd: Cmd) -> Hit:
    return ("crontab-remove", "") if "-r" in flags_of(cmd.args) else None


def systemctl(cmd: Cmd) -> Hit:
    verb = positionals(cmd.args, _SYSTEMCTL_VALUES)[:1]
    return ("systemctl-disable", verb[0]) if verb in (["disable"], ["mask"]) else None


HOST_RULES: dict[str, Callable[[Cmd], Hit]] = {
    "rm": rm,
    "unlink": unlink,
    "rmdir": unlink,
    "mv": mv,
    "chmod": chmod,
    "chown": chown,
    "chgrp": chown,
    "dd": dd,
    "mkfs": mkfs,
    "mke2fs": mkfs,
    "mkswap": mkfs,
    "find": find,
    "shred": shred,
    "truncate": shred,
    "wipefs": wipefs,
    "usermod": usermod,
    "passwd": passwd,
    "chattr": chattr,
    "kill": kill,
    "pkill": pkill,
    "killall": killall,
    "crontab": crontab,
    "systemctl": systemctl,
}
