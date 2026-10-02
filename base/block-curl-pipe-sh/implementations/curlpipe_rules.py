"""What fetches, what runs its input as code, and what counts as a verify step: judged per parsed command."""

import re
import shlex
from itertools import pairwise

from chock_shellparse import Cmd, commands, flags_of, operands
from curlpipe_programs import SHELLS, STDIN_PATHS, is_interpreter, program, resolve
from curlpipe_runners import runner_inner

NONE, WEAK, STRONG = 0, 1, 2
DEPTH = 4
#: How many leading arguments of an unlisted wrapper are tried as the start of the command it runs.
WRAP_SCAN = 8
#: Stand-ins for a substitution's output: a download, a raw socket or one-liner read, a read of the stage's stdin,
#: a path to a downloader (`$(which curl)`), anything else.
PH = {STRONG: "__chock_fetch__", WEAK: "__chock_netread__"}
PH_STDIN, PH_FETCHER, PH_OTHER = "__chock_stdin__", "__chock_fetcher__", "__chock_subst__"
#: `$(cat file)` / `<(cat file)`: the file named after the marker, ended by \x1f.
PH_FILE = "__chock_file__"

FETCHERS = frozenset(
    (
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
    )
)
NETREADERS = frozenset(("nc", "ncat", "netcat", "socat", "telnet"))
VERIFIERS = frozenset(
    ("sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "shasum", "md5sum", "b2sum", "b3sum", "cksum")
)
SIGNERS = frozenset(("gpgv", "minisign", "signify", "cosign", "slsa-verifier", "get-filehash"))
AWKS = frozenset(("awk", "gawk", "mawk", "nawk"))
#: Tools that take data, never a command, so a shell name among their arguments is a file or a pattern.
DATA_TOOLS = frozenset(
    (
        *("grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "jq", "yq", "xmllint", "tee", "cat"),
        *("tac", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "xxd", "base64", "gunzip", "zcat", "gzip"),
        *("bzip2", "xz", "tar", "unzip", "file", "git", "gpg", "gpgv", "less", "more", "diff", "cmp", "patch"),
        *("printf", "echo", "find", "ls", "stat", "mkdir", "touch", "cp", "mv", "rm", "ln", "chmod", "chown"),
        *("install", "curl", "wget", "scp", "rsync", "xargs", "parallel", "docker", "podman", "kubectl"),
    )
)
_NET = re.compile(
    r"https?://|urllib|urlopen|requests\.|http\.client|httpx|\bfetch\(|https?\.get\(|LWP|HTTP::Tiny|open-uri"
    r"|Net::HTTP|file_get_contents|Invoke-WebRequest|DownloadString|socket",
    re.IGNORECASE,
)
_EXEC = re.compile(
    r"\b(?:exec|eval|Function|system|popen|subprocess|child_process|execSync|spawn|loadstring|Invoke-Expression|iex)\b"
)
_STDIN_READ = re.compile(r"stdin|readFileSync\(\s*0|<STDIN>|\$<|ARGF|io\.read|\$input|Console\]::In", re.IGNORECASE)
_AWK_RUN = re.compile(r"system\s*\(|\|\s*\"|\|&")


def stdin_runs(cmd: Cmd, depth: int = 0) -> bool:
    """True when what arrives on this command's stdin is run as code."""
    cmd = resolve(cmd)
    if cmd.name in ("-", "iex", "invoke-expression") or cmd.name.startswith(("$", "__chock_")):
        return True
    if cmd.name in ("source", "."):
        return bool(set(cmd.args[:1]) & STDIN_PATHS)
    if is_interpreter(cmd.name):
        kind, body = program(cmd)
        if kind == "code" and cmd.name in SHELLS:
            return _any_stdin(body, depth)
        return kind == "stdin" or (kind == "code" and bool(_EXEC.search(body) and _STDIN_READ.search(body)))
    inner = runner_inner(cmd)
    if inner is not None:
        return inner == "" or _any_stdin(inner, depth)
    return _stdin_tool(cmd) or _wrapped(cmd, depth)


def _wrapped(cmd: Cmd, depth: int) -> bool:
    """A wrapper not listed anywhere (strace, setarch, chronic ...): some later argument starts a stdin-reading shell."""
    if cmd.name in DATA_TOOLS or depth:
        return False
    starts = [i for i, arg in enumerate(cmd.args[:WRAP_SCAN]) if not arg.startswith("-")]
    return any(
        stdin_runs(first, 1) for i in starts for first in commands(shlex.join(cmd.args[i : i + 2 * WRAP_SCAN]))[:1]
    )


def _program_file_is_stdin(args: list[str]) -> bool:
    """`-f -` or `-f /dev/stdin`: make and awk reading their program from stdin."""
    return any(a in ("-f", "--file") and b in STDIN_PATHS for a, b in pairwise(args))


def _stdin_tool(cmd: Cmd) -> bool:
    """Tools that run their stdin some other way: at/batch, crontab -, make -f -, awk system(), parallel, cmd."""
    args = cmd.args
    if cmd.name in ("at", "batch"):
        return "-f" not in args
    if cmd.name == "crontab":
        return not args or "-" in args
    if cmd.name in ("make", "gmake"):
        return _program_file_is_stdin(args) or any(a in ("--file=-", "--makefile=-", "-f-") for a in args)
    if cmd.name in AWKS:
        found = [a for a in operands(args) if not a.startswith("-")]
        return _program_file_is_stdin(args) or (bool(found) and _AWK_RUN.search(found[0]) is not None)
    if cmd.name in ("parallel", "cmd"):
        return not [a for a in args if not a.startswith(("-", "/"))] and "/c" not in [a.lower() for a in args]
    return False


def _any_stdin(text: str, depth: int) -> bool:
    return depth < DEPTH and any(stdin_runs(c, depth + 1) for c in commands(text))


def executes(cmd: Cmd, ph: str, depth: int = 0) -> bool:
    """True when this command runs the output a placeholder stands for as code."""
    cmd = resolve(cmd)
    if cmd.name.startswith(ph) or (ph in cmd.reads and stdin_runs(cmd, depth)):
        return True
    if cmd.name in ("make", "gmake"):
        return any(a in ("-f", "--file") and ph in b for a, b in pairwise(cmd.args))
    if cmd.name in ("source", "."):
        return any(ph in arg for arg in cmd.args[:1])
    if is_interpreter(cmd.name):
        kind, body = program(cmd)
        return kind in ("code", "script") and ph in body
    inner = runner_inner(cmd)
    return bool(inner) and depth < DEPTH and any(executes(c, ph, depth + 1) for c in commands(inner or ""))


def inner_cmds(cmd: Cmd, depth: int = 0) -> list[Cmd]:
    """The commands another tool (ssh, su -c, docker exec, cmd /c ...) runs for this one, at every level."""
    inner = runner_inner(resolve(cmd)) if depth < DEPTH else None
    return [c for first in commands(inner or "") for c in (first, *inner_cmds(first, depth + 1))]


def fetch_strength(cmd: Cmd, depth: int = 0) -> int:
    """STRONG for a downloader or a command carrying a download's output, WEAK for a raw socket or net one-liner."""
    cmd = resolve(cmd)
    words = [cmd.name, *cmd.args, *cmd.reads]
    if cmd.name in FETCHERS or cmd.name == PH_FETCHER or any(PH[STRONG] in word for word in words):
        return STRONG
    socket = any(r.startswith(("/dev/tcp/", "/dev/udp/")) for r in cmd.reads)
    weak = cmd.name in NETREADERS or socket or any(PH[WEAK] in word for word in words)
    if weak or net_one_liner(cmd):
        return WEAK
    inner = runner_inner(cmd) if depth < DEPTH else None
    return max([NONE, *(fetch_strength(c, depth + 1) for c in commands(inner or ""))])


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
