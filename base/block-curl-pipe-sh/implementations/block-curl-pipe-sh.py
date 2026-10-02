#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a network download wired into a shell or interpreter (pipe, substitution, here-string, download-then-run).
# Best effort, not a security boundary: aliases, functions, variables and encoded commands are out of reach.

import os
import re
import shlex
import sys

from chock_shellparse import Cmd, commands, is_powershell, operands
from curlpipe_chain import chain
from curlpipe_lex import Stage, Sub, Word, lex
from curlpipe_rules import (
    NONE,
    PH,
    PH_OTHER,
    PH_STDIN,
    SHELLS,
    STDIN_PATHS,
    STRONG,
    WEAK,
    code_fetches_and_runs,
    executes,
    fetch_and_exec,
    fetch_strength,
    is_interpreter,
    program,
    stdin_runs,
)

BLOCK, ASK = 1, 3
DEPTH = 4
Verdict = tuple[int, str] | None
PRINTERS = frozenset(("echo", "printf", "print", ":", "write-host", "write-output", "grep", "egrep", "fgrep", "rg"))
MESSAGE_TOOLS = frozenset(("git", "gh", "glab", "hg", "svn", "jj"))
TEXT_FLAGS = frozenset(("-m", "--message", "-b", "--body", "-t", "--title", "--notes"))
READERS = frozenset(("cat", "head", "tail", "tee", "dd"))
XARGS_VALUES = frozenset(("-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--replace"))
FETCH_HINT = re.compile(
    r"(?<![\w-])(?:curl|wget2?|fetch|aria2c|lynx|https?|xh|curlie|iwr|irm|invoke-webrequest|invoke-restmethod"
    r"|start-bitstransfer|nc|ncat|netcat|socat|telnet)(?![\w-])|/dev/(?:tcp|udp)/|downloadstring|urlopen|urllib",
    re.IGNORECASE,
)
CRUDE_FETCH = re.compile(
    r"(?<![\w.-])(?:curl|wget2?|aria2c|lynx|xh|curlie|iwr|irm|invoke-webrequest|invoke-restmethod|nc|ncat|socat)"
    r"(?![\w-])|downloadstring|/dev/tcp/",
    re.IGNORECASE,
)
CRUDE_RUN = re.compile(
    r"(?<![\w./-])(?:sh|bash|zsh|dash|ksh|ash|mksh|fish|csh|tcsh|busybox|(?:python|pypy)[0-9.]*|perl|ruby|node"
    r"|nodejs|php|lua|deno|bun|pwsh|powershell|iex|invoke-expression|eval|source|su)(?![\w-])|\$\{?shell\b"
    r"|(?:^|[\s;&|(])\.\s",
    re.IGNORECASE,
)
PS_FETCH = re.compile(
    r"(?<![\w-])(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget|start-bitstransfer)(?![\w-])"
    r"|net\.webclient|downloadstring|downloaddata|downloadfile",
    re.IGNORECASE,
)
PS_RUN = re.compile(
    r"\|\s*&?\s*(?:iex|invoke-expression)(?![\w-])|(?<![\w-])(?:iex|invoke-expression)\s*(?:[($'\"]|-c)"
    r"|\[scriptblock\]::create",
    re.IGNORECASE,
)
ADVICE = "Download it to a file, read or verify it (sha256sum -c, gpg --verify), then run it as a separate step."


def refuse(what: str) -> Verdict:
    return BLOCK, f"BLOCKED: {what}, so remote code would run unread. {ADVICE}"


def wired(strength: int, into: str) -> Verdict:
    if strength == STRONG:
        return refuse(f"a network download is wired into {into}")
    return ASK, (
        f"CONFIRM: a raw network read (nc, socat, /dev/tcp or an interpreter one-liner) is wired into {into}. "
        "Ask the person to confirm; better, save it to a file and read it first."
    )


def strongest(found: list[Verdict]) -> Verdict:
    """A block wins over an ask, which wins over silence."""
    real = [v for v in found if v]
    return next((v for v in real if v[0] == BLOCK), real[0] if real else None)


def judge(text: str, depth: int = 0) -> Verdict:
    """The verdict for one command line, recursing into substitutions and quoted bodies."""
    if depth > DEPTH:
        return refuse("a download nested too deep to read is in this command") if FETCH_HINT.search(text) else None
    if is_powershell(text):
        text = text.replace("`", "").replace("\\", "/")
    pipelines, broken = lex(text)
    found = [_powershell(text), _crude(text) if broken else None]
    ran: list[Cmd] = []
    found += [_pipeline(stages, depth, ran) for stages in pipelines]
    strength, name = chain(ran)
    found.append(wired(strength, f"{name}, which is downloaded and run in one command") if strength else None)
    return strongest(found)


def _powershell(text: str) -> Verdict:
    if PS_FETCH.search(text) and PS_RUN.search(text):
        return refuse("a PowerShell download is passed to Invoke-Expression (iex)")
    return None


def _crude(text: str) -> Verdict:
    """Fail closed when the quoting never balances: a downloader and an interpreter named anywhere is a refusal."""
    if CRUDE_FETCH.search(text) and CRUDE_RUN.search(text):
        return refuse(
            "this command could not be parsed (unbalanced quote or trailing backslash) and names a downloader and a shell or interpreter"
        )
    return None


def _pipeline(stages: list[Stage], depth: int, ran: list[Cmd]) -> Verdict:
    fed, found = NONE, []
    for stage in stages:
        cmds = stage_cmds(stage, depth)
        ran += cmds
        found.append(_stage(stage, cmds, fed, depth))
        fed = max([fed, *(fetch_strength(c) for c in cmds)])
    return strongest(found)


def stage_cmds(stage: Stage, depth: int) -> list[Cmd]:
    if stage.group is not None:
        return [c for stages in stage.group for inner in stages for c in stage_cmds(inner, depth)]
    return commands(render(stage, depth))


def render(stage: Stage, depth: int) -> str:
    """The stage as plain shell text for chock_shellparse, each substitution replaced by a placeholder word."""
    parts = [shlex.quote(fill(word, depth)) for word in stage.words]
    for op, word in stage.redirs:
        if op in ("<", ">", ">>", ">|", "&>", "&>>"):
            parts += [op, shlex.quote(fill(word, depth))]
    return " ".join(parts)


def fill(word: Word, depth: int) -> str:
    return "".join(part if isinstance(part, str) else _placeholder(part, depth) for part in word.parts)


def _placeholder(sub: Sub, depth: int) -> str:
    if sub.kind == ">(":
        return PH_OTHER
    strength = body_strength(sub.body, depth + 1)
    if strength:
        return PH[strength]
    cmds = commands(sub.body)
    reads = bool(cmds) and cmds[0].name in READERS and set(operands(cmds[0].args)) <= STDIN_PATHS
    return PH_STDIN if reads or any(set(c.reads) & STDIN_PATHS for c in cmds) else PH_OTHER


def body_strength(text: str, depth: int) -> int:
    """The strongest fetch anywhere in a substitution body: its output is then fetched content."""
    if depth > DEPTH:
        return STRONG if FETCH_HINT.search(text) else NONE
    stages = [stage for pipeline in lex(text)[0] for stage in pipeline]
    return max([NONE, *(fetch_strength(c) for stage in stages for c in stage_cmds(stage, depth))])


def _stage(stage: Stage, cmds: list[Cmd], fed: int, depth: int) -> Verdict:
    found = [judge(sub.body, depth + 1) for sub in stage.subs()]
    if stage.group is not None:
        found += [_pipeline(stages, depth, []) for stages in stage.group]
    exempt = _text_values(cmds)
    for word in stage.words:
        body = "".join(p if isinstance(p, str) else PH_OTHER for p in word.parts)
        if fill(word, depth) not in exempt and FETCH_HINT.search(body) and re.search(r"[\s|;&<>`$]", body):
            found.append(judge(body, depth + 1))
    for doc in stage.heredocs:
        if any(c.name in SHELLS for c in cmds):
            found.append(judge(doc, depth + 1))
        elif any(is_interpreter(c.name) for c in cmds) and code_fetches_and_runs(doc):
            found.append(wired(WEAK, "an interpreter that runs it"))
    found.append(_wiring(stage, cmds, fed, depth))
    found += [wired(WEAK, f"{c.name}, which runs it") for c in cmds if fetch_and_exec(c)]
    return strongest(found)


def _wiring(stage: Stage, cmds: list[Cmd], fed: int, depth: int) -> Verdict:
    for strength in (STRONG, WEAK):
        ph = PH[strength]
        here = any(op == "<<<" and ph in fill(word, depth) for op, word in stage.redirs)
        hit = next((c.name for c in cmds if executes(c, ph)), None)
        if hit is not None or (here and any(stdin_runs(c) for c in cmds)):
            return wired(strength, f"{hit or 'a here-string'} that runs it as code")
    out = [sub for sub in stage.subs() if sub.kind == ">("]
    if any(stdin_runs(c) for sub in out for c in commands(sub.body)):
        fed = max([fed, *(fetch_strength(c) for c in cmds)])
        if fed:
            return wired(fed, "a >(...) process substitution that runs it")
    if not fed:
        return None
    hit = next((c.name for c in cmds if stdin_runs(c) or executes(c, PH_STDIN)), None)
    words = [fill(w, depth) for w in stage.words]
    if hit is None and (_xargs_runs(words) or _root_shell(words)):
        hit = words[0]
    return wired(fed, hit) if hit is not None else None


def _xargs_runs(words: list[str]) -> bool:
    """xargs (or parallel) turning the download into the arguments of a shell -c, eval or interpreter."""
    names = [re.sub(r"\.exe$", "", w.replace("\\", "/").rsplit("/", 1)[-1].lower()) for w in words]
    at = next((i for i, name in enumerate(names) if name in ("xargs", "parallel")), -1)
    i = at + 1
    while 0 < i < len(words) and words[i].startswith("-"):
        i += 2 if words[i] in XARGS_VALUES else 1
    if at < 0 or i >= len(words):
        return False
    inner = Cmd(names[i], words[i + 1 :], {}, [], [], "")
    return names[i] in ("eval", "source", ".") or (is_interpreter(names[i]) and program(inner)[0] in ("stdin", "code"))


def _root_shell(words: list[str]) -> bool:
    """`sudo -s` / `sudo -i` with no command: a root shell that reads the download from stdin."""
    flags = [w for w in words[1:] if w.startswith("-")]
    root = words[:1] in (["sudo"], ["doas"]) and len(flags) == len(words) - 1
    return root and any(f in ("--shell", "--login") or (f[1:2] != "-" and set(f[1:]) & {"s", "i"}) for f in flags)


def _text_values(cmds: list[Cmd]) -> set[str]:
    """Arguments that are text, never run: what a printer or grep prints, a commit or PR message."""
    found: set[str] = set()
    for cmd in cmds:
        if cmd.name in PRINTERS:
            found.update(cmd.args)
        elif cmd.name in MESSAGE_TOOLS:
            found.update(cmd.args[i + 1] for i, a in enumerate(cmd.args[:-1]) if a in TEXT_FLAGS)
            found.update(a.split("=", 1)[1] for a in cmd.args if a.split("=", 1)[0] in TEXT_FLAGS and "=" in a)
    return found


def check(raw: str) -> Verdict:
    """The verdict for a command line; under CHOCK_ARGV_FALLBACK the crude reading is applied too."""
    fallback = _crude(raw) if os.environ.get("CHOCK_ARGV_FALLBACK") == "1" else None
    return strongest([fallback, judge(raw)])


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        verdict = check(os.environ.get("CHOCK_RAW_COMMAND") or " ".join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-curl-pipe-sh: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if verdict:
        print(verdict[1], file=sys.stderr)
    return verdict[0] if verdict else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
