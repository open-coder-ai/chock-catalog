"""What fetches, what runs its input as code, and what runs a file: judged per parsed command (stdlib only)."""

import re
from typing import NamedTuple

from chock_shellparse import Cmd, abbreviates, commands, flags_of
from curlpipe_runners import runner_inner

NONE, WEAK, STRONG = 0, 1, 2
#: Stand-ins for a substitution's output: a download, a raw socket or one-liner read, a read of the stage's stdin.
PH = {STRONG: "__chock_fetch__", WEAK: "__chock_netread__"}
PH_STDIN, PH_OTHER = "__chock_stdin__", "__chock_subst__"

FETCHERS = frozenset(
    [
        "curl",
        "wget",
        "wget2",
        "fetch",
        "aria2c",
        "lynx",
        "http",
        "https",
        "xh",
        "curlie",
        "iwr",
        "irm",
        "invoke-webrequest",
        "invoke-restmethod",
        "start-bitstransfer",
    ]
)
NETREADERS = frozenset(["nc", "ncat", "netcat", "socat", "telnet"])
SHELLS = frozenset(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "posh", "fish", "csh", "tcsh"])
STDIN_PATHS = frozenset(("-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"))
VERIFIERS = frozenset(
    ["sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "shasum", "md5sum", "b2sum", "b3sum", "cksum"]
)
SIGNERS = frozenset(["gpgv", "minisign", "signify", "cosign", "slsa-verifier", "get-filehash"])


class Family(NamedTuple):
    """How one interpreter family names its program: code flags, module flags, flags taking a value, code letters."""

    code: frozenset[str]
    module: frozenset[str] = frozenset()
    values: frozenset[str] = frozenset()
    letters: str = ""
    stops: str = ""


def _f(code: str, module: str = "", values: str = "", letters: str = "") -> Family:
    """`letters` is "code letters|letters that take the rest of the cluster as a value"."""
    code_letters, _, stops = letters.partition("|")
    return Family(frozenset(code.split()), frozenset(module.split()), frozenset(values.split()), code_letters, stops)


FAMILIES = {
    "python": _f("-c", "-m", "-W -X --check-hash-based-pycs"),
    "pypy": _f("-c", "-m", "-W -X"),
    "perl": _f("", "", "-I -M -m", "eE|IMmFixC0ld"),
    "ruby": _f("", "", "-I -r -C -E -F", "e|IrCEFxK0i"),
    "node": _f("-e --eval -p --print", "", "-r --require --import --loader -C --conditions"),
    "php": _f("-r -B -R -F -E", "", "-c -d -z"),
    "lua": _f("-e", "", "-l"),
    "osascript": _f("-e", "", "-l -s"),
    "rscript": _f("-e"),
    "tclsh": _f(""),
    "wish": _f(""),
    "sh": _f("", "", "-o +o -O +O --rcfile --init-file", "c|oO"),
}
_FAMILY = re.compile(r"(python|pypy|perl|ruby|node|php|lua|osascript|rscript|tclsh|wish)(?:js|jit)?[0-9.]*")
_NET = re.compile(
    r"https?://|urllib|urlopen|requests\.|http\.client|httpx|\bfetch\(|https?\.get\(|LWP|HTTP::Tiny|open-uri"
    r"|Net::HTTP|file_get_contents|Invoke-WebRequest|DownloadString|socket",
    re.IGNORECASE,
)
_EXEC = re.compile(
    r"\b(?:exec|eval|Function|system|popen|subprocess|child_process|execSync|spawn|loadstring|Invoke-Expression|iex)\b"
)


def family(name: str) -> Family | None:
    if name in SHELLS:
        return FAMILIES["sh"]
    found = _FAMILY.fullmatch(name)
    return FAMILIES[found.group(1)] if found else None


def is_interpreter(name: str) -> bool:
    return name in ("deno", "bun", "pwsh", "powershell") or family(name) is not None


def resolve(cmd: Cmd) -> Cmd:
    """busybox runs its first argument as the tool: `busybox sh` is sh."""
    if cmd.name == "busybox" and cmd.args:
        return cmd._replace(name=cmd.args[0].lower(), args=cmd.args[1:])
    return cmd


def program(cmd: Cmd) -> tuple[str, str]:
    """How an interpreter gets its program: ('stdin'|'code'|'script'|'module', the code or script text)."""
    cmd = resolve(cmd)
    if cmd.name in ("pwsh", "powershell"):
        return _powershell(cmd.args)
    if cmd.name in ("deno", "bun"):
        return (
            ("stdin", "-")
            if "-" in cmd.args
            else ("code", "")
            if {"eval", "-e", "--eval"} & set(cmd.args)
            else ("", "")
        )
    fam, args, i = family(cmd.name) or FAMILIES["sh"], cmd.args, 0
    while i < len(args):
        arg, value = args[i], args[i + 1] if i + 1 < len(args) else ""
        kind = _flag_kind(fam, arg)
        if arg in STDIN_PATHS:
            return "stdin", arg
        if kind:
            return kind, value
        if arg == "--" or not arg.startswith(("-", "+")):
            script = value if arg == "--" else arg
            return ("script", script) if script else ("stdin", "")
        i += 2 if arg in fam.values else 1
    return "stdin", ""


def _flag_kind(fam: Family, arg: str) -> str:
    """'code' or 'module' when `arg` is the flag that names the program, 'stdin' for a shell's -s, else ''."""
    if arg in fam.code or _in_cluster(arg, fam.letters, fam.stops):
        return "code"
    if arg in fam.module:
        return "module"
    return "stdin" if fam is FAMILIES["sh"] and _in_cluster(arg, "s", fam.stops) else ""


def _in_cluster(arg: str, letters: str, stops: str) -> bool:
    """Whether a short-option cluster (-xec) carries one of `letters` before a letter that takes a value."""
    if not letters or arg[:1] != "-" or arg[1:2] == "-":
        return False
    for char in arg[1:]:
        if char in letters:
            return True
        if char in stops:
            return False
    return False


_PS_SWITCHES = ("-noprofile", "-nologo", "-noninteractive", "-noexit", "-sta", "-mta", "-login", "-interactive")


def _powershell(args: list[str]) -> tuple[str, str]:
    i = 0
    while i < len(args):
        low, value = args[i].lower(), args[i + 1] if i + 1 < len(args) else ""
        if abbreviates(low, "-file", 2):
            return ("stdin", value) if value == "-" else ("script", value)
        if abbreviates(low, "-command", 2) or abbreviates(low, "-encodedcommand", 2) or low == "-ec":
            return ("stdin", value) if value == "-" else ("code", value)
        if not low.startswith("-"):
            return "script", args[i]
        switch = low in ("-l", "-i") or any(abbreviates(low, full, 3) for full in _PS_SWITCHES)
        i += 1 if switch else 2
    return "stdin", ""


def stdin_runs(cmd: Cmd, depth: int = 0) -> bool:
    """True when what arrives on this command's stdin is run as code."""
    cmd = resolve(cmd)
    if cmd.name in ("-", "iex", "invoke-expression") or cmd.name.startswith("$"):
        return True
    if cmd.name in ("source", "."):
        return bool(set(cmd.args[:1]) & STDIN_PATHS)
    if is_interpreter(cmd.name):
        kind, body = program(cmd)
        return kind == "stdin" or (kind == "code" and cmd.name in SHELLS and _any_stdin(body, depth))
    inner = runner_inner(cmd)
    if inner is None:
        return False
    return inner == "" or _any_stdin(inner, depth)


def _any_stdin(text: str, depth: int) -> bool:
    return depth < 4 and any(stdin_runs(c, depth + 1) for c in commands(text))  # noqa: PLR2004 -- the parser's depth


def executes(cmd: Cmd, ph: str, depth: int = 0) -> bool:
    """True when this command runs the output a placeholder stands for as code."""
    cmd = resolve(cmd)
    if cmd.name == ph:
        return True
    if cmd.name in ("source", "."):
        return any(ph in arg for arg in cmd.args[:1])
    if is_interpreter(cmd.name):
        kind, body = program(cmd)
        return (kind in ("code", "script") and ph in body) or (ph in cmd.reads and kind == "stdin")
    inner = runner_inner(cmd)
    return bool(inner) and depth < 4 and any(executes(c, ph, depth + 1) for c in commands(inner or ""))  # noqa: PLR2004


def fetch_strength(cmd: Cmd) -> int:
    """STRONG for a downloader or a command carrying a download's output, WEAK for a raw socket or net one-liner."""
    cmd = resolve(cmd)
    words = [cmd.name, *cmd.args, *cmd.reads]
    if cmd.name in FETCHERS or any(PH[STRONG] in word for word in words):
        return STRONG
    weak = (
        cmd.name in NETREADERS or any(PH[WEAK] in w for w in words) or any(r.startswith("/dev/tcp/") for r in cmd.reads)
    )
    return WEAK if weak or net_one_liner(cmd) else NONE


def net_one_liner(cmd: Cmd) -> bool:
    if not is_interpreter(cmd.name) or cmd.name in SHELLS:
        return False
    kind, body = program(cmd)
    return kind == "code" and _NET.search(body) is not None


def code_fetches_and_runs(code: str) -> bool:
    return _NET.search(code) is not None and _EXEC.search(code) is not None


def fetch_and_exec(cmd: Cmd) -> bool:
    """An interpreter one-liner that both reads from the network and runs what it read."""
    return net_one_liner(cmd) and code_fetches_and_runs(program(cmd)[1])


def verifies(cmd: Cmd) -> bool:
    """A checksum or signature check: sha256sum -c, gpg --verify, cosign verify, minisign -V and the like."""
    flags = flags_of(cmd.args)
    if cmd.name in VERIFIERS:
        return "-c" in flags or "--check" in flags
    if cmd.name in ("gpg", "gpg2"):
        return "--verify" in flags
    if cmd.name == "openssl":
        return "-verify" in cmd.args or "-signature" in cmd.args
    return cmd.name in SIGNERS
