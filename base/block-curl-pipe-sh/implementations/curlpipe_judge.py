"""Judge one command line: pipes, substitutions, quoted bodies, here-strings, printed scripts and download chains."""

import re
import shlex

from chock_shellparse import Cmd, commands, operands
from curlpipe_chain import basename, chain
from curlpipe_lex import Stage, Sub, Word, lex
from curlpipe_programs import SHELLS, STDIN_PATHS, is_interpreter, program
from curlpipe_rules import (
    DEPTH,
    FETCHERS,
    NONE,
    PH,
    PH_FETCHER,
    PH_FILE,
    PH_OTHER,
    PH_STDIN,
    STRONG,
    WEAK,
    code_fetches_and_runs,
    executes,
    fetch_and_exec,
    fetch_strength,
    inner_cmds,
    stdin_runs,
)
from curlpipe_verdict import FETCH_HINT, Verdict, crude, powershell, refuse, strongest, wired

PRINTERS = frozenset(("echo", "printf", "print", ":", "write-host", "write-output", "grep", "egrep", "fgrep", "rg"))
MESSAGE_TOOLS = frozenset(("git", "gh", "glab", "hg", "svn", "jj"))
TEXT_FLAGS = frozenset(("-m", "--message", "-b", "--body", "-t", "--title", "--notes"))
READERS = frozenset(("cat", "head", "tail", "tee", "dd"))
LOCATORS = frozenset(("which", "command", "type", "whereis"))
XARGS_VALUES = frozenset(("-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--replace"))
_IFS = re.compile(r"\$\{IFS[^}]*\}|\$IFS\b")
_VAR = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
_ASSIGN = re.compile(r"([A-Za-z_]\w*)=(.*)", re.DOTALL)
_FILE_PH = re.compile(PH_FILE + r"([^\x1f]*)\x1f")
_DYNAMIC = re.compile(r"[*?{]|\[[^\]]+\]|\$")
_CRON_TIME = re.compile(r"^\s*(?:@\w+|(?:[-\d*/,\w]+\s+){5})", re.MULTILINE)
FILE_READERS = frozenset(("cat", "tac", "head", "tail", "zcat", "gzcat"))


class Judge:
    """One command line's reading: its nesting depth and the variables it assigns, in order."""

    def __init__(self, depth: int = 0, env: dict[str, str] | None = None) -> None:
        self.depth, self.vars = depth, dict(env or {})

    def deeper(self, text: str) -> Verdict:
        return Judge(self.depth + 1, self.vars).line(text)

    def line(self, text: str) -> Verdict:
        """The verdict for a command line, recursing into substitutions and quoted bodies."""
        if self.depth > DEPTH:
            return refuse("a download nested too deep to read is in this command") if FETCH_HINT.search(text) else None
        text = _IFS.sub(" ", text)
        pipelines, broken = lex(text)
        found = [powershell(text), crude(text) if broken else None]
        ran: list[Cmd] = []
        found += [self.pipeline(stages, ran) for stages in pipelines]
        strength, name = chain(ran)
        found.append(wired(strength, f"{name}, which is downloaded and run in one command") if strength else None)
        return strongest(found)

    def strength(self, text: str) -> int:
        """The strongest fetch anywhere in a substitution body: its output is then fetched content."""
        if self.depth > DEPTH:
            return STRONG if FETCH_HINT.search(text) else NONE
        stages = [stage for pipeline in lex(text)[0] for stage in pipeline]
        return max([NONE, *(fetch_strength(c) for stage in stages for c in self.cmds(stage))])

    def pipeline(self, stages: list[Stage], ran: list[Cmd]) -> Verdict:
        fed, printed, found, earlier = NONE, [], [], []
        for stage in stages:
            cmds = self.cmds(stage)
            ran += [c for first in cmds for c in (first, *inner_cmds(first))]
            ran += self.files_run(stage, cmds, earlier) + self.files_kept(cmds, fed)
            found.append(self.stage(stage, cmds, fed))
            if any(stdin_runs(c) for c in cmds):
                found += [self.deeper(_cron_body(text, cmds)) for text in printed]
            fed = max([fed, *(fetch_strength(c) for c in cmds)])
            printed += self.prints(stage, cmds)
            earlier += [basename(a) for c in cmds for a in operands(c.args)]
            self.assign(stage)
        return strongest(found)

    def files_run(self, stage: Stage, cmds: list[Cmd], earlier: list[str]) -> list[Cmd]:
        """Files this stage runs without naming them: `sh < f`, `cat f | sh`, `eval "$(cat f)"`, `. <(cat f)`."""
        words = [self.fill(w) for w in [*stage.words, *(w for _, w in stage.redirs)]]
        named = [name for text in words for name in _FILE_PH.findall(text)]
        reads = [basename(r) for c in cmds for r in c.reads]
        runs = any(stdin_runs(c) for c in cmds)
        hit = (named if any(executes(c, PH_FILE) for c in cmds) else []) + (reads + earlier if runs else [])
        return [Cmd(name, [], {}, [], [], "") for name in hit if name]

    @staticmethod
    def files_kept(cmds: list[Cmd], fed: int) -> list[Cmd]:
        """A download written out by a later stage (`curl u | tee f`, `| cat > f`, `| dd of=f`) is a download to f."""
        if not fed:
            return []
        files = [w for c in cmds for w in c.writes]
        files += [a for c in cmds if c.name == "tee" for a in operands(c.args)]
        files += [a[3:] for c in cmds if c.name == "dd" for a in c.args if a.startswith("of=")]
        return [Cmd(PH[fed], [], {}, files, [], "")] if files else []

    def cmds(self, stage: Stage) -> list[Cmd]:
        if stage.group is not None:
            return [c for stages in stage.group for inner in stages for c in self.cmds(inner)]
        lead = next((i for i, w in enumerate(stage.words) if not _ASSIGN.fullmatch(w.source)), -1)
        parts = [self.quoted(word, lead=i == lead) for i, word in enumerate(stage.words)]
        for op, word in stage.redirs:
            if op in ("<", ">", ">>", ">|", "&>", "&>>"):
                parts += [op, shlex.quote(self.fill(word))]
        return commands(" ".join(parts))

    def quoted(self, word: Word, *, lead: bool) -> str:
        """The word for re-parsing; an unquoted variable holding `sh -s` in command position splits into words."""
        text = self.fill(word)
        return text if lead and not word.quoted and "$" in word.source and text.split() != [text] else shlex.quote(text)

    def fill(self, word: Word) -> str:
        """The word as the shell would pass it, each substitution a placeholder and known variables expanded."""
        text = "".join(part if isinstance(part, str) else self.placeholder(part) for part in word.parts)
        return _VAR.sub(lambda m: self.vars.get(m.group(1) or m.group(2), m.group(0)), text)

    def placeholder(self, sub: Sub) -> str:
        if sub.kind == ">(" or not sub.body.strip():
            return PH_OTHER if sub.kind == ">(" else ""
        cmds = commands(sub.body)
        printed = _printed(sub.body, cmds)
        strength = NONE if printed is not None else Judge(self.depth + 1, self.vars).strength(sub.body)
        if printed is not None or strength:
            return printed if printed is not None else PH[strength]
        if cmds and cmds[0].name in LOCATORS and set(cmds[0].args) & FETCHERS:
            return PH_FETCHER
        if len(cmds) == 1 and cmds[0].name in FILE_READERS:
            files = [a for a in operands(cmds[0].args) if a not in STDIN_PATHS]
            if files and "$(" not in sub.body:
                return "".join(f"{PH_FILE}{basename(a)}\x1f" for a in files)
        reads = bool(cmds) and cmds[0].name in READERS and set(operands(cmds[0].args)) <= STDIN_PATHS
        return PH_STDIN if reads or any(set(c.reads) & STDIN_PATHS for c in cmds) else PH_OTHER

    def assign(self, stage: Stage) -> None:
        """Remember `name=value` words so a later `$name` reads as what it holds (one command line only)."""
        for word in stage.words:
            found = _ASSIGN.fullmatch(self.fill(word))
            if found:
                self.vars[found.group(1)] = found.group(2)

    def prints(self, stage: Stage, cmds: list[Cmd]) -> list[str]:
        """Text this stage writes to the next one: echo/printf arguments, a heredoc or here-string it reads."""
        found = [" ".join(c.args).replace("\\n", "\n") for c in cmds if c.name in ("echo", "printf", "print")]
        found += stage.heredocs if not any(stdin_runs(c) for c in cmds) else []
        return found + [self.fill(word) for op, word in stage.redirs if op == "<<<"]

    def stage(self, stage: Stage, cmds: list[Cmd], fed: int) -> Verdict:
        found = [self.deeper(sub.body) for sub in stage.subs()]
        if stage.group is not None:
            found += [self.pipeline(stages, []) for stages in stage.group]
        exempt = _text_values(cmds)
        for word in stage.words:
            body = "".join(p if isinstance(p, str) else PH_OTHER for p in word.parts)
            if self.fill(word) not in exempt and FETCH_HINT.search(body) and re.search(r"[\s|;&<>`$]", body):
                found.append(self.deeper(body))
        runs = any(stdin_runs(c) for c in cmds)
        for doc in stage.heredocs:
            if any(c.name in SHELLS for c in cmds):
                found.append(self.deeper(doc))
            elif any(is_interpreter(c.name) for c in cmds) and code_fetches_and_runs(doc):
                found.append(wired(WEAK, "an interpreter that runs it"))
        found += [self.deeper(self.fill(word)) for op, word in stage.redirs if op == "<<<" and runs]
        found.append(self.wiring(stage, cmds, fed))
        found += [wired(WEAK, f"{c.name}, which runs it") for c in cmds if fetch_and_exec(c)]
        return strongest(found)

    def wiring(self, stage: Stage, cmds: list[Cmd], fed: int) -> Verdict:
        for strength in (STRONG, WEAK):
            ph = PH[strength]
            here = any(op == "<<<" and ph in self.fill(word) for op, word in stage.redirs)
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
        words = [self.fill(w) for w in stage.words]
        lead = next((w for w in words if not _ASSIGN.fullmatch(w)), "")
        if _DYNAMIC.search(lead):
            return wired(fed, "a command whose name is built at run time")
        hit = next((c.name for c in cmds if stdin_runs(c) or executes(c, PH_STDIN)), None)
        if hit is None and (_xargs_runs(words) or _root_shell(words)):
            hit = words[0]
        return wired(fed, hit) if hit is not None else None


def _cron_body(text: str, cmds: list[Cmd]) -> str:
    """Text printed into `crontab -` is read as crontab lines: the five time fields come off."""
    return _CRON_TIME.sub("", text) if any(c.name == "crontab" for c in cmds) else text


def _printed(body: str, cmds: list[Cmd]) -> str | None:
    """What `$(echo x)` or `$(printf %s x)` prints, when that is all the substitution does."""
    if len(cmds) != 1 or "$(" in body or "`" in body or cmds[0].name not in ("echo", "printf"):
        return None
    args = cmds[0].args
    if cmds[0].name == "echo":
        return " ".join(a for a in args if a not in ("-n", "-e", "-E"))
    if args and "%" not in args[0]:
        return args[0]
    return "".join(args[1:]) if args[:1] in (["%s"], ["%b"]) else None


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
