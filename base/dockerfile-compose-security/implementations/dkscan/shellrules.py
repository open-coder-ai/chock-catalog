"""Rules over the shell text of RUN (continuations joined, heredoc bodies appended) and over ENV and ARG text.

Command position: line or heredoc-line start, after ; & | ( { a quote, $( or backtick, then/do/else or
find's -exec, behind RUN with its flags (ONBUILD too), sudo/env/exec/nohup/timeout-style wrappers and
VAR=value assignments. A command whose name is built at run time ($cmd, aliases) is not seen. Every
repeat is bounded, so a crafted line costs time linear in its length.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator

from dkscan import limits
from dkscan.dockerfile import Instr
from dkscan.rules import Ctx, Hit

SEP = r"(?:^|[\n;&|(`{]|(?<![^\s\[,=(])[\"']|\$\(|\b(?:then|do|else)\s|\s-exec(?:dir)?\s)\s{0,64}(?i:(?:ONBUILD\s+)?RUN(?:\s+--\S{1,256}){0,32}\s+)?"
WRAP = (
    r"(?:(?:sudo|doas|env|exec|command|nohup|nice|time|stdbuf|xargs|timeout\s+\S{1,64})(?:\s+-{1,2}[\w-]{1,64}(?:=\S{0,128})?){0,32}\s+"
    r"|[A-Za-z_]\w{0,64}=\S{0,128}\s+){0,32}"
)
ARGS = r"[^;\n|&]{0,4096}?"
RUNS = r"(?:[^;\n|&]|&(?![&>])){0,4096}"


def prog(name: str) -> str:
    return rf"{SEP}\s{{0,64}}{WRAP}(?:[^\s;&|]{{0,128}}/)?(?:{name})(?![\w.-])"


FETCH = r"curl|wget2?|aria2c|lynx|(?i:iwr|irm|invoke-webrequest|invoke-restmethod)"
INTERP = r"(?:ba|z|da|k|a|c|tc|mk)?sh|fish|busybox\s+sh|python[0-9.]*|perl|ruby|node|php|lua|deno|bun|(?i:pwsh|powershell|iex|invoke-expression)"
STDIN_TAIL = r"(?:(?=\s*(?:$|[;&|)\n\"'`]))|(?:\s+-\w{1,32}){0,32}?\s+(?:-s|--|-)(?=\s|$))"
FETCH_EXEC = re.compile(
    rf"{prog(FETCH)}{RUNS}(?:\|(?!\|){RUNS}){{0,3}}?\|(?!\|)\s{{0,64}}{WRAP}[\"']?(?:\S{{0,128}}/)?(?:{INTERP})(?![\w.-]){STDIN_TAIL}"
    rf"|{SEP}\s{{0,64}}(?:(?:ba|z|da|k|a)?sh|eval|source|\.)(?:\s+-\S{{1,64}}){{0,32}}\s+(?:<<<\s*|<\s*)?[\"']?(?:\$\(|<\(|`)\s*(?:sudo\s+)?(?:{FETCH})(?![\w-])"
    r"|(?i:\b(?:iex|invoke-expression)\s*\(*\s*(?:irm|iwr|invoke-webrequest|invoke-restmethod|new-object\s+(?:system\.)?net\.webclient))",
    re.MULTILINE,
)
ASSIGN = r"[\"']?(?:\s*[=:]\s*|[ \t]+)[\"']?"
TLS_OFF = re.compile(
    rf"{prog('curl')}{ARGS}(?<!\S)(?:-(?!-)[A-Za-z0-9]{{0,32}}k[A-Za-z0-9]{{0,32}}|--insecure)(?![\w-])"
    r"|\binsecure\b[^\n;&|]{0,512}?>>?\s*\S{0,256}\.curlrc|--no-check-certificate\b|\bcheck_certificate\s*=\s*off\b|--check-certificate=false\b"
    rf"|(?i:trusted[-_]host)|PYTHONHTTPSVERIFY{ASSIGN}0\b|(?i:strict[-_]ssl){ASSIGN}(?i:false|0)\b"
    rf"|GIT_SSL_NO_VERIFY(?:=|[ \t]+)[\"']?[^\s\"'\\]|(?i:\bssl_?verify){ASSIGN}(?i:false|0|no|off)\b",
    re.MULTILINE,
)
NODE_TLS = re.compile(rf"NODE_TLS_REJECT_UNAUTHORIZED{ASSIGN}0\b")
SIGNATURE = re.compile(
    r"--allow-unauthenticated\b|--allow-insecure-repositories\b|--allow-untrusted\b|--nogpgcheck\b|--force-yes\b"
    r"|--no-gpg-checks\b|Allow(?:Unauthenticated|InsecureRepositories|DowngradeToInsecureRepositories)[\"']?\s*[= ]\s*[\"']?(?i:true|1|yes)"
    r"|\[[^\]\n]{0,512}\btrusted=yes\b[^\]\n]{0,512}\]|(?i:\bgpgcheck\s*=\s*0\b)"
    rf"|{prog('rpm')}{ARGS}--no(?:digest|signature|verify|filedigest)\b",
    re.MULTILINE,
)
SUDO = re.compile(
    rf"{SEP}\s{{0,64}}(?:[A-Za-z_]\w{{0,64}}=\S{{0,128}}\s+){{0,32}}(?:\S{{0,128}}/)?sudo(?![\w.-])|\bopenssh-server\b"
    r"|\b(?:install|add)\b[^;\n|&]{0,4096}?(?<![\w.-])(?:sudo|openssh)(?![\w.-])",
    re.MULTILINE,
)
PASSWORDS = re.compile(
    rf"{prog('chpasswd')}|{prog('useradd|adduser|usermod')}{ARGS}(?<!\S)(?:-p|--password)(?:[=\s]|$)"
    rf"|{prog('passwd')}{ARGS}(?<!\S)(?:-d|--delete|--stdin)\b",
    re.MULTILINE,
)
GIT_CLONE = re.compile(
    rf"{prog('git')}(?:\s+-[cC]\s+\S{{1,256}}|\s+--[\w-]{{1,64}}(?:=\S{{0,256}})?){{0,32}}\s+clone\b", re.MULTILINE
)
#: A clone counts as pinned when a later checkout, switch, reset, fetch or --revision names a 40-hex commit.
PINNED = re.compile(
    r"\b(?:checkout|switch|reset|fetch)\b[^;\n|&]{0,512}?(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])"
    r"|--revision[=\s][\"']?[0-9a-fA-F]{40}(?![0-9a-fA-F])"
)
CHMOD = re.compile(rf"{prog('chmod')}([^;\n|&]{{0,4096}})", re.MULTILINE)
INSTALL_MODE = re.compile(rf"{prog('install')}{ARGS}(?<!\S)-m\s*([^\s;&|]{{1,64}})", re.MULTILINE)
WORDS = re.compile(r"[\s,\"'\[\]]+")
NUMERIC = re.compile(r"[0-7]{3,5}")
SYMBOLIC = re.compile(r"([ugoa]*)([-+=])([rwxXst]*)")
LEAD = re.compile(r"[\s;&|(`{\"'$]*")
PERMS = 3
STICKY = 1


def begin(text: str, found: re.Match[str]) -> int:
    """Where a match's command starts: past the separator and blanks the pattern consumed before it."""
    return LEAD.match(text, found.start()).end()  # type: ignore[union-attr]


def spans_lines(instr: Instr, found: re.Match[str]) -> bool:
    return instr.line_at(begin(instr.text, found)) != instr.line_at(found.end() - 1)


def _hit(rule: str, instr: Instr, found: re.Match[str] | None, why: str) -> Hit:
    return Hit(rule, instr.line_at(begin(instr.text, found)) if found else instr.line, instr.text, why)


def _numeric(mode: str) -> str:
    special = int(mode[:-PERMS] or "0", 8)
    if special & 0o6:
        return "sets the setuid or setgid bit"
    if int(mode[-1]) & 0o2 and not special & STICKY:
        return "makes the file world-writable"
    return ""


def _symbolic(mode: str) -> str:
    for who, op, perms in SYMBOLIC.findall(mode):
        if op != "-" and "s" in perms:
            return "sets the setuid or setgid bit"
        if op != "-" and "w" in perms and ("a" in who or "o" in who):
            return "makes the file world-writable"
    return ""


def chmod_mode(args: str) -> str:
    """Why a chmod's (or COPY --chmod's, install -m's) mode is too broad, or ""."""
    for word in WORDS.split(args):
        if not word or (word.startswith("-") and not SYMBOLIC.fullmatch(word)):
            continue
        return _numeric(word) if NUMERIC.fullmatch(word) else _symbolic(word)
    return ""


#: One finding per RUN for each: rule, pattern, why.
ONCE = (
    ("dk-signature-bypass", SIGNATURE, "package signature checks switched off"),
    ("dk-sudo-sshd", SUDO, "sudo or an SSH server in the image"),
    ("dk-chpasswd", PASSWORDS, "a password set or removed in the image"),
)


def judgeable(instr: Instr) -> Iterator[Hit]:
    """A dk-unjudgeable finding when the text runs past what the patterns read in full."""
    if why := limits.unjudgeable(instr.text):
        yield _hit("dk-unjudgeable", instr, None, f"too large to judge: {why}")


def run_hits(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    """Every shell-text finding in a RUN (or ONBUILD RUN). A one-line fetch-exec is left to
    block-fetch-exec-in-files only where that gate is installed and reads the path."""
    yield from judgeable(instr)
    if len(instr.text) > limits.TEXT:
        return
    for found in FETCH_EXEC.finditer(instr.text):
        if spans_lines(instr, found) or not ctx.fetch_exec_elsewhere:
            yield _hit("dk-fetch-exec", instr, found, "a download piped into an interpreter")
    yield from tls_hits(instr, ctx)
    for rule, pattern, why in ONCE:
        if found := pattern.search(instr.text):
            yield _hit(rule, instr, found, why)
    yield from _multi_hits(instr)


def _multi_hits(instr: Instr) -> Iterator[Hit]:
    text = instr.text
    pins = [found.start() for found in PINNED.finditer(text)]
    for found in GIT_CLONE.finditer(text):
        if bisect.bisect_right(pins, found.end()) == len(pins):
            yield _hit("dk-git-clone-unpinned", instr, found, "git clone with no 40-hex checkout after it")
    for pattern in (CHMOD, INSTALL_MODE):
        for found in pattern.finditer(text):
            if why := chmod_mode(found.group(1)):
                yield _hit("dk-chmod-setuid", instr, found, f"mode {why}")
    if "insecure" in instr.flags.get("security", ""):
        yield _hit("dk-run-insecure", instr, None, "RUN --security=insecure runs the step privileged")


def tls_hits(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    """TLS verification switched off in RUN, ENV or ARG text. A one-line NODE_TLS form is left to
    agentic-code-security only where it is installed and reads the file."""
    found = TLS_OFF.search(instr.text)
    if not found:
        found = next(
            (m for m in NODE_TLS.finditer(instr.text) if spans_lines(instr, m) or not ctx.node_tls_elsewhere), None
        )
    if found:
        yield _hit("dk-tls-off", instr, found, "TLS certificate verification switched off")
