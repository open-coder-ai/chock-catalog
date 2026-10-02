"""Download-then-run inside one command line: a file a fetcher wrote, later run with no verify step between."""

import re

from chock_shellparse import Cmd, abbreviates, operands
from curlpipe_programs import is_interpreter, program, resolve
from curlpipe_rules import NONE, fetch_strength, verifies

_URL = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_STDOUT = frozenset(("-", "/dev/stdout", "/dev/fd/1"))
#: Per downloader: (short option letter, long options) naming the output file, and whether it saves by default.
_OUTPUT = {
    "curl": ("o", ("--output",), False),
    "wget": ("O", ("--output-document",), True),
    "wget2": ("O", ("--output-document",), True),
    "aria2c": ("o", ("--out",), True),
    "fetch": ("o", ("--output",), True),
    "http": ("o", ("--output",), False),
    "https": ("o", ("--output",), False),
    "xh": ("o", ("--output",), False),
    "curlie": ("o", ("--output",), False),
}


def basename(path: str) -> str:
    """The last path segment, lower-cased, without a URL's query or fragment."""
    return re.split(r"[?#]", path.replace("\\", "/"))[0].rstrip("/").rsplit("/", 1)[-1].lower()


def _value(args: list[str], letter: str, longs: tuple[str, ...]) -> list[str]:
    found = []
    for i, arg in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if arg in longs:
            found.append(nxt)
        elif arg.startswith(tuple(f"{name}=" for name in longs)):
            found.append(arg.split("=", 1)[1])
        elif arg[:1] == "-" and arg[1:2] != "-" and letter in arg[1:]:
            rest = arg[arg.index(letter, 1) + 1 :]
            found.append(rest or nxt)
    return found


def _remote_names(cmd: Cmd) -> list[str]:
    return [arg for arg in operands(cmd.args) if _URL.match(arg)]


def outputs(cmd: Cmd) -> list[str]:
    """Basenames of the files a download writes: -o/-O/--output, PowerShell -OutFile, or the URL's own name."""
    cmd = resolve(cmd)
    files = list(cmd.writes)
    if cmd.name in _OUTPUT:
        letter, longs, default = _OUTPUT[cmd.name]
        named = _value(cmd.args, letter, longs)
        remote = cmd.name == "curl" and any(
            a in ("--remote-name", "--remote-name-all") or _short(a, "O") for a in cmd.args
        )
        downloads = cmd.name in ("http", "https", "xh") and ("--download" in cmd.args or "-d" in cmd.args)
        files += named or (_remote_names(cmd) if default or remote or downloads else [])
    for i, arg in enumerate(cmd.args[:-1]):
        low = arg.lower()
        if abbreviates(low, "-outfile", 5) or abbreviates(low, "-destination", 3):
            files.append(cmd.args[i + 1])
    return [basename(f) for f in files if f and f not in _STDOUT]


def _short(arg: str, letter: str) -> bool:
    return arg[:1] == "-" and arg[1:2] != "-" and letter in arg[1:]


def run_target(cmd: Cmd) -> str:
    """The file this command runs: the program itself, an interpreter's script, or what source reads."""
    cmd = resolve(cmd)
    if is_interpreter(cmd.name):
        kind, text = program(cmd)
        return basename(text) if kind == "script" else ""
    if cmd.name in ("source", "."):
        return basename(cmd.args[0]) if cmd.args else ""
    return cmd.name


def chain(cmds: list[Cmd]) -> tuple[int, str]:
    """(strength, file) for the first downloaded file run later in the line with no verify step between."""
    got: dict[str, int] = {}
    for cmd in cmds:
        if verifies(cmd):
            got.clear()
            continue
        target = run_target(cmd)
        if target in got:
            return got[target], target
        strength = fetch_strength(cmd)
        if strength:
            got.update(dict.fromkeys(outputs(cmd), strength))
    return NONE, ""
