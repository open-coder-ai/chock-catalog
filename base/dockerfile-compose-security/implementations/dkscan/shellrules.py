"""Rules over the shell script of a RUN: its commands (dkscan.shell) and the literal keys and flags in its text.

Commands are matched by program name after wrappers, assignments, quotes and escapes, so padding,
quoting or splitting a name does not hide it. Text rules are literal keys (GIT_SSL_NO_VERIFY,
sslverify=0, --nogpgcheck) that hold wherever they appear. An instruction longer than TEXT, or
nested deeper than the lexer follows, is reported as too large to judge and not scanned further.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from dkscan import cmdrules, resolve, shell
from dkscan.dockerfile import Instr
from dkscan.rules import Ctx, Hit

TEXT = 64 * 1024
NESTED_SCRIPTS = 4
ID_SPACE = 1 << 20
ASSIGN = r"[\"']?(?:\s*[=:]\s*|[ \t]+)[\"']?"
TLS_OFF = re.compile(
    r"--no-check-certificate\b|\bcheck_certificate\s*=\s*off\b|--check-certificate=false\b"
    rf"|(?i:trusted[-_]host)|PYTHONHTTPSVERIFY{ASSIGN}0\b|(?i:strict[-_]ssl){ASSIGN}(?i:false|0)\b"
    rf"|GIT_SSL_NO_VERIFY(?:=|[ \t]+)[\"']?[^\s\"'\\]|(?i:\bssl_?verify){ASSIGN}(?i:false|0|no|off)\b"
)
NODE_TLS = re.compile(rf"NODE_TLS_REJECT_UNAUTHORIZED{ASSIGN}0\b")
SIGNATURE = re.compile(
    r"--allow-unauthenticated\b|--allow-insecure-repositories\b|--allow-untrusted\b|--nogpgcheck\b|--force-yes\b"
    r"|--no-gpg-checks\b|Allow(?:Unauthenticated|InsecureRepositories|DowngradeToInsecureRepositories)[\"']?\s*[= ]\s*[\"']?(?i:true|1|yes)"
    r"|\btrusted=yes\b|(?i:\bgpgcheck\s*=\s*0\b)"
)
PS_WEBCLIENT = re.compile(r"(?i)\b(?:iex|invoke-expression)\s*\(*\s*new-object\s+(?:system\.)?net\.webclient")
#: The spellings block-fetch-exec-in-files (HP03) reads on one line; only these are left to it.
HP03_PIPE = re.compile(
    r"(?:\S*/)?(?<![\w.-])(?:curl|wget2?|aria2c|lynx)(?![\w-])[^;&|\n#]*\|\s*(?:(?:sudo|env)\s+)?(?:\S*/)?(?:ba|z|da|k|a)?sh(?![\w.-])"
)
HP03_SUBST = re.compile(
    r"(?<![\w.-])(?:eval|source|(?:ba|z|da|k|a)?sh)(?:\s+-\w+)?\s+[\"']?(?:\$\(|<\()\s*(?:curl|wget2?)(?![\w-])"
)
DEEP = "too large to judge: nesting deeper than the gate follows"


def _hit(rule: str, instr: Instr, offset: int, why: str) -> Hit:
    return Hit(rule, instr.line_at(offset), instr.text, why)


def _shift(ident: int, offset: int) -> int:
    return ident + offset if ident > 0 else ident


def script(instr: Instr) -> tuple[list[shell.Cmd], bool]:
    """The RUN's commands (the exec form as one command), `sh -c` scripts followed, and whether nesting ran too deep."""
    form = instr.exec_form()
    if form is not None:
        whole = shell.Cmd(1, tuple(form), instr.body_at, -1, -1, (instr.body_at,) * len(form))
        cmds, deep = ([whole] if form else []), False
    else:
        cmds, deep = shell.commands(" " * instr.body_at + instr.text[instr.body_at :])
    queue = cmds
    for depth in range(1, NESTED_SCRIPTS + 1):
        found: list[shell.Cmd] = []
        for cmd in queue:
            prog, args, _ = cmdrules.program(cmd)
            for text in resolve.inline_scripts(prog, args, cmd.words):
                inner, inner_deep = shell.commands(text)
                deep = deep or inner_deep
                offset = depth * ID_SPACE * ID_SPACE + cmd.id * ID_SPACE
                found += [
                    c._replace(
                        id=c.id + offset,
                        parent=_shift(c.parent, offset),
                        piped_from=_shift(c.piped_from, offset),
                        start=cmd.start,
                        offsets=(cmd.start,) * len(c.words),
                    )
                    for c in inner
                ]
        cmds = cmds + found
        queue = found
    unfollowed = any(resolve.inline_scripts(*cmdrules.program(cmd)[:2], cmd.words) for cmd in queue)
    return cmds, deep or unfollowed


def judgeable(instr: Instr) -> Iterator[Hit]:
    """The dk-unjudgeable finding for an instruction too long (else too deeply nested) to read in full."""
    why = f"too large to judge: longer than {TEXT // 1024} KiB" if len(instr.text) > TEXT else DEEP
    yield _hit("dk-unjudgeable", instr, 0, why)


def run_hits(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    """Every finding in a RUN (or ONBUILD RUN)."""
    if len(instr.text) > TEXT or instr.deep:
        yield from judgeable(instr)
        return
    cmds, deep = script(instr)
    if deep:
        yield _hit("dk-unjudgeable", instr, 0, DEEP)
    yield from _fetch_exec(instr, cmds, ctx)
    for cmd in cmds:
        prog, args, wrappers = cmdrules.program(cmd)
        for rule, why in cmdrules.simple(prog, args, wrappers):
            yield _hit(rule, instr, cmd.start, why)
    for cmd in cmdrules.clones(cmds):
        yield _hit("dk-git-clone-unpinned", instr, cmd.start, "git clone with no 40-hex checkout after it")
    yield from tls_hits(instr, ctx)
    if found := SIGNATURE.search(instr.text):
        yield _hit("dk-signature-bypass", instr, found.start(), "package signature checks switched off")
    if "insecure" in instr.flags.get("security", ""):
        yield _hit("dk-run-insecure", instr, 0, "RUN --security=insecure runs the step privileged")


def _fetch_exec(instr: Instr, cmds: list[shell.Cmd], ctx: Ctx) -> Iterator[Hit]:
    for fetch, runner in cmdrules.fetch_exec(cmds):
        if not (ctx.fetch_exec_elsewhere and _one_line_hp03(instr, fetch, runner)):
            yield _hit("dk-fetch-exec", instr, min(fetch.start, runner.start), "a download piped into an interpreter")
    if (found := PS_WEBCLIENT.search(instr.text)) and not ctx.fetch_exec_elsewhere:
        yield _hit("dk-fetch-exec", instr, found.start(), "a download run by iex")


def _one_line_hp03(instr: Instr, fetch: shell.Cmd, runner: shell.Cmd) -> bool:
    """Whether the pair sits on one physical line in a spelling block-fetch-exec-in-files reads.

    Each pattern is tried once, at the fetch (or the substituting runner) program word, so the check is linear.
    """
    if instr.line_at(fetch.start) != instr.line_at(runner.start):
        return False
    pipe_at, subst_at = _word_at(fetch), _word_at(runner)
    return bool(HP03_PIPE.match(instr.text, pipe_at) or HP03_SUBST.match(instr.text, subst_at))


def _word_at(cmd: shell.Cmd) -> int:
    at = resolve.resolve(cmd.words)[0]
    return cmd.offsets[at] if 0 <= at < len(cmd.offsets) else cmd.start


def tls_hits(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    """TLS verification switched off by a literal key in RUN, ENV or ARG text."""
    found = TLS_OFF.search(instr.text)
    if not found:
        found = next((m for m in NODE_TLS.finditer(instr.text) if _spans(instr, m) or not ctx.node_tls_elsewhere), None)
    if found:
        yield _hit("dk-tls-off", instr, found.start(), "TLS certificate verification switched off")


def _spans(instr: Instr, found: re.Match[str]) -> bool:
    return instr.line_at(found.start()) != instr.line_at(found.end() - 1)
