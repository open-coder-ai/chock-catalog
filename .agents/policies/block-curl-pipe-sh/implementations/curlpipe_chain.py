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


#: An interpreter's own code that runs a file by name: exec(open(f).read()), runpy, subprocess, include, dofile.
_RUNS_FILE = re.compile(
    r"\b(?:exec|eval|execfile|runpy|compile|system|popen|subprocess|spawn|execSync|dofile|loadfile|include|include_once|require_once)\b"
)
_LAUNCHERS = frozenset(("start-process", "saps", "start", "invoke-item", "ii"))
_LAUNCH_VALUES = ("-argumentlist", "-workingdirectory", "-windowstyle", "-verb", "-credential")


def _launched(args: list[str]) -> str:
    """The file Start-Process / Invoke-Item / start opens: -FilePath's value, else the first operand."""
    skip = False
    for i, arg in enumerate(args):
        low = arg.lower()
        if abbreviates(low, "-filepath", 3) and i + 1 < len(args):
            return args[i + 1]
        if skip or not arg.startswith("-"):
            if not skip:
                return arg
            skip = False
        elif any(abbreviates(low, full, 4) for full in _LAUNCH_VALUES):
            skip = True
    return ""


def key(name: str) -> str:
    """A file's identity for matching a download to a run: its basename without a Windows .exe."""
    return re.sub(r"\.exe$", "", name)


def run_target(cmd: Cmd) -> str:
    """The file this command runs: the program itself, an interpreter's script, or what source reads."""
    cmd = resolve(cmd)
    if cmd.name in _LAUNCHERS:
        return basename(_launched(cmd.args))
    if is_interpreter(cmd.name):
        kind, text = program(cmd)
        return basename(text) if kind == "script" else ""
    if cmd.name in ("source", "."):
        return basename(cmd.args[0]) if cmd.args else ""
    return cmd.name


def _runs_downloaded(cmd: Cmd, got: dict[str, int]) -> str:
    """The downloaded file an interpreter's -c/-e code or -m module runs (`python -c "exec(open('f.py').read())"`)."""
    cmd = resolve(cmd)
    if not is_interpreter(cmd.name):
        return ""
    kind, body = program(cmd)
    if kind == "module":
        return next((k for k in (key(body), key(body + ".py")) if k in got), "")
    if kind != "code" or not _RUNS_FILE.search(body):
        return ""
    return next((k for k in got if re.search(rf"(?<![\w.-]){re.escape(k)}(?![\w-])", body)), "")


def chain(cmds: list[Cmd]) -> tuple[int, str]:
    """(strength, file) for the first downloaded file run later in the line with no verify step between."""
    got: dict[str, int] = {}
    for cmd in cmds:
        if verifies(cmd):
            got.clear()
            continue
        target = key(run_target(cmd))
        target = target if target in got else _runs_downloaded(cmd, got)
        if target in got:
            return got[target], target
        strength = fetch_strength(cmd)
        if strength:
            got.update(dict.fromkeys(map(key, outputs(cmd)), strength))
    return NONE, ""
