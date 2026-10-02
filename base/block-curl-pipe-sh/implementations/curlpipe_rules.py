"""What fetches, what runs its input as code, and what counts as a verify step: judged per parsed command."""

import re

from chock_shellparse import Cmd, commands, flags_of, operands
from curlpipe_programs import SHELLS, STDIN_PATHS, is_interpreter, program, resolve
from curlpipe_runners import runner_inner

NONE, WEAK, STRONG = 0, 1, 2
DEPTH = 4
#: Stand-ins for a substitution's output: a download, a raw socket or one-liner read, a read of the stage's stdin,
#: a path to a downloader (`$(which curl)`), anything else.
PH = {STRONG: "__chock_fetch__", WEAK: "__chock_netread__"}
PH_STDIN, PH_FETCHER, PH_OTHER = "__chock_stdin__", "__chock_fetcher__", "__chock_subst__"

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
    return _stdin_tool(cmd)


def _stdin_tool(cmd: Cmd) -> bool:
    """Tools that run their stdin some other way: at/batch, crontab -, make -f -, awk system(), parallel, cmd."""
    args = cmd.args
    if cmd.name in ("at", "batch"):
        return "-f" not in args
    if cmd.name == "crontab":
        return not args or "-" in args
    if cmd.name in ("make", "gmake"):
        return any(a in ("--file=-", "--makefile=-", "-f-") for a in args) or ("-f" in args and "-" in args)
    if cmd.name in AWKS:
        found = [a for a in operands(args) if not a.startswith("-")]
        return bool(found) and _AWK_RUN.search(found[0]) is not None
    if cmd.name in ("parallel", "cmd"):
        return not [a for a in args if not a.startswith(("-", "/"))] and "/c" not in [a.lower() for a in args]
    return False


def _any_stdin(text: str, depth: int) -> bool:
    return depth < DEPTH and any(stdin_runs(c, depth + 1) for c in commands(text))


def executes(cmd: Cmd, ph: str, depth: int = 0) -> bool:
    """True when this command runs the output a placeholder stands for as code."""
    cmd = resolve(cmd)
    if cmd.name == ph or (ph in cmd.reads and stdin_runs(cmd, depth)):
        return True
    if cmd.name in ("source", "."):
        return any(ph in arg for arg in cmd.args[:1])
    if is_interpreter(cmd.name):
        kind, body = program(cmd)
        return kind in ("code", "script") and ph in body
    inner = runner_inner(cmd)
    return bool(inner) and depth < DEPTH and any(executes(c, ph, depth + 1) for c in commands(inner or ""))


def fetch_strength(cmd: Cmd) -> int:
    """STRONG for a downloader or a command carrying a download's output, WEAK for a raw socket or net one-liner."""
    cmd = resolve(cmd)
    words = [cmd.name, *cmd.args, *cmd.reads]
    if cmd.name in FETCHERS or cmd.name == PH_FETCHER or any(PH[STRONG] in word for word in words):
        return STRONG
    socket = any(r.startswith(("/dev/tcp/", "/dev/udp/")) for r in cmd.reads)
    weak = cmd.name in NETREADERS or socket or any(PH[WEAK] in word for word in words)
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
