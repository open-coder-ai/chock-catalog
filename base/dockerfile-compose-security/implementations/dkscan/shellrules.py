"""Rules over the shell text of RUN (continuations joined, heredoc bodies appended) and over ENV and ARG text.

Command position: line or heredoc-line start, after ; & | ( { a quote, $( or backtick, or then/do/else,
behind RUN with its flags (ONBUILD too), sudo/env/exec/nohup/timeout-style wrappers and VAR=value
assignments. A command whose name is built at run time ($cmd, aliases) is not seen.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from dkscan.dockerfile import Instr
from dkscan.rules import Ctx, Hit

SEP = r"(?:^|[\n;&|(`{\"']|\$\(|\b(?:then|do|else)\s)\s*(?i:(?:ONBUILD\s+)?RUN(?:\s+--\S+)*\s+)?"
WRAP = (
    r"(?:(?:sudo|doas|env|exec|command|nohup|nice|time|stdbuf|xargs|timeout\s+\S+)(?:\s+-{1,2}[\w-]+(?:=\S*)?)*\s+"
    r"|[A-Za-z_]\w*=\S*\s+)*"
)
ARGS = r"[^;\n|&]*?"


def prog(name: str) -> str:
    return rf"{SEP}\s*{WRAP}(?:[^\s;&|]*/)?(?:{name})(?![\w.-])"


FETCH = r"curl|wget2?|aria2c|lynx|(?i:iwr|irm|invoke-webrequest|invoke-restmethod)"
INTERP = r"(?:ba|z|da|k|a|c|tc|mk)?sh|fish|busybox\s+sh|python[0-9.]*|perl|ruby|node|php|lua|deno|bun|(?i:pwsh|powershell|iex|invoke-expression)"
STDIN_TAIL = r"(?:(?=\s*(?:$|[;&|)\n\"'`]))|(?:\s+-[\w]+)*?\s+(?:-s|--|-)(?=\s|$))"
FETCH_EXEC = re.compile(
    rf"{prog(FETCH)}(?:[^;\n|&]|&(?![&>]))*(?:\|(?!\|)(?:[^;\n|&]|&(?![&>]))*){{0,3}}?\|(?!\|)\s*{WRAP}[\"']?(?:\S*/)?(?:{INTERP})(?![\w.-]){STDIN_TAIL}"
    rf"|{SEP}\s*(?:(?:ba|z|da|k|a)?sh|eval|source|\.)(?:\s+-\S+)*\s+(?:<<<\s*|<\s*)?[\"']?(?:\$\(|<\(|`)\s*(?:sudo\s+)?(?:{FETCH})(?![\w-])"
    r"|(?i:\b(?:iex|invoke-expression)\s*\(*\s*(?:irm|iwr|invoke-webrequest|invoke-restmethod|new-object\s+(?:system\.)?net\.webclient))",
    re.MULTILINE,
)
ASSIGN = r"[\"']?(?:\s*[=:]\s*|[ \t]+)[\"']?"
TLS_OFF = re.compile(
    rf"{prog('curl')}{ARGS}(?<!\S)(?:-(?!-)[A-Za-z0-9]*k[A-Za-z0-9]*|--insecure)(?![\w-])"
    r"|\binsecure\b[^\n;&|]*>>?\s*\S*\.curlrc|--no-check-certificate\b|\bcheck_certificate\s*=\s*off\b|--check-certificate=false\b"
    rf"|(?i:trusted[-_]host)|PYTHONHTTPSVERIFY{ASSIGN}0\b|(?i:strict[-_]ssl){ASSIGN}(?i:false|0)\b"
    rf"|GIT_SSL_NO_VERIFY(?:=|[ \t]+)[\"']?[^\s\"'\\]|(?i:\bssl_?verify){ASSIGN}(?i:false|0|no|off)\b",
    re.MULTILINE,
)
NODE_TLS = re.compile(rf"NODE_TLS_REJECT_UNAUTHORIZED{ASSIGN}0\b")
SIGNATURE = re.compile(
    r"--allow-unauthenticated\b|--allow-insecure-repositories\b|--allow-untrusted\b|--nogpgcheck\b|--force-yes\b"
    r"|--no-gpg-checks\b|Allow(?:Unauthenticated|InsecureRepositories|DowngradeToInsecureRepositories)[\"']?\s*[= ]\s*[\"']?(?i:true|1|yes)"
    r"|\[[^\]\n]*\btrusted=yes\b[^\]\n]*\]|(?i:\bgpgcheck\s*=\s*0\b)"
    rf"|{prog('rpm')}{ARGS}--no(?:digest|signature|verify|filedigest)\b",
    re.MULTILINE,
)
SUDO = re.compile(rf"{SEP}\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:\S*/)?sudo(?![\w.-])|\bopenssh-server\b", re.MULTILINE)
PASSWORDS = re.compile(
    rf"{prog('chpasswd')}|{prog('useradd|adduser|usermod')}{ARGS}(?<!\S)(?:-p|--password)(?:[=\s]|$)|{prog('passwd')}{ARGS}(?<!\S)-d\b",
    re.MULTILINE,
)
GIT_CLONE = re.compile(rf"{prog('git')}(?:\s+-[cC]\s+\S+)*\s+clone\b", re.MULTILINE)
SHA = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
CHMOD = re.compile(rf"{prog('chmod')}([^;\n|&]*)", re.MULTILINE)
NUMERIC = re.compile(r"[0-7]{3,5}")
SYMBOLIC = re.compile(r"([ugoa]*)([-+=])([rwxXst]*)")
LEAD = re.compile(r"[\s;&|(`{\"'$]*")
PERMS = 3
STICKY = 1


def begin(text: str, found: re.Match[str]) -> int:
    """Where a match's command starts: past the separator and blanks the pattern consumed before it."""
    return LEAD.match(text, found.start()).end()  # type: ignore[union-attr]


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
    """Why a chmod's mode is too broad, or ""."""
    for word in args.split():
        if word.startswith("-") and not SYMBOLIC.fullmatch(word):
            continue
        return _numeric(word) if NUMERIC.fullmatch(word) else _symbolic(word)
    return ""


#: One finding per RUN for each: rule, pattern, why.
ONCE = (
    ("dk-signature-bypass", SIGNATURE, "package signature checks switched off"),
    ("dk-sudo-sshd", SUDO, "sudo or an SSH server in the image"),
    ("dk-chpasswd", PASSWORDS, "a password set or removed in the image"),
)


def run_hits(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    """Every shell-text finding in a RUN (or ONBUILD RUN); fetch-exec only where it spans lines."""
    text = instr.text
    for found in FETCH_EXEC.finditer(text):
        if instr.line_at(begin(text, found)) != instr.line_at(found.end() - 1):
            yield _hit("dk-fetch-exec", instr, found, "a download piped into an interpreter across lines")
    yield from tls_hits(instr, ctx)
    for rule, pattern, why in ONCE:
        if found := pattern.search(text):
            yield _hit(rule, instr, found, why)
    yield from _multi_hits(instr)


def _multi_hits(instr: Instr) -> Iterator[Hit]:
    text = instr.text
    for found in GIT_CLONE.finditer(text):
        if not SHA.search(text, found.end()):
            yield _hit("dk-git-clone-unpinned", instr, found, "git clone with no 40-hex checkout after it")
    for found in CHMOD.finditer(text):
        if why := chmod_mode(found.group(1)):
            yield _hit("dk-chmod-setuid", instr, found, f"chmod {why}")
    if "insecure" in instr.flags.get("security", ""):
        yield _hit("dk-run-insecure", instr, None, "RUN --security=insecure runs the step privileged")


def tls_hits(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    """TLS verification switched off in RUN, ENV or ARG text."""
    found = TLS_OFF.search(instr.text) or (NODE_TLS.search(instr.text) if ctx.node_tls else None)
    if found:
        yield _hit("dk-tls-off", instr, found, "TLS certificate verification switched off")
