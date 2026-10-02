#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse git --no-verify, the other ways of switching git hooks off, and an agent setting a person-only override.

import os
import re
import shlex
import sys
from itertools import pairwise

from chock_shellparse import Cmd, commands, git_parts
from hook_bypass import (
    DECLARERS,
    END,
    HOOK_SUBS,
    HOOKS_KEY,
    PS_PATH,
    PS_SETTERS,
    SHELLS,
    aliases,
    asks_for,
    config_pairs,
    config_writes,
    declared,
    env_asks,
    env_hits,
    launched,
    normalise,
    rebase_execs,
    skips_verify,
    submodule_scripts,
    uninstalls,
    without_bodies,
)

BLOCK, ASK = 1, 3
DEPTH = 3  # aliases, rebase --exec and submodule foreach read this many levels deep
# Person-only variables: the engine reads CHOCK_ALLOW (answers an ask gate), CHOCK_AGENT_COMMIT (0/false says a person is
# committing) and the agent markers CLAUDECODE / AI_AGENT; limit-diff-size reads CHOCK_ALLOW_LARGE_DIFF, CHOCK_DIFF_LIMIT;
# CHOCK_ROLLOUT lowers the compiled gates to ask or warn, and CHOCK_GATE_LOG=0 switches off the record of what that let through.
OVERRIDE = re.compile(r"CHOCK_(?:AGENT_COMMIT|DIFF_LIMIT|ROLLOUT|GATE_LOG|ALLOW\w*)|CLAUDECODE|AI_AGENT", re.IGNORECASE)
REMOVAL = frozenset(("CLAUDECODE", "AI_AGENT", "CHOCK_AGENT_COMMIT"))  # hiding these makes an agent's commit a person's
MARKERS = "(CLAUDECODE|AI_AGENT|CHOCK_AGENT_COMMIT)(?!\\w)"
WIPED = "CHOCK_ENV_WIPED"
ASSIGN = re.compile(r"([A-Za-z_]\w*)\+?=")
# Spellings the lexer drops are rewritten to the plain NAME=v it knows; text inside quotes stays data either way.
REWRITES = tuple(
    (re.compile(pattern, re.IGNORECASE), repl)
    for pattern, repl in (
        (
            r"(?:\$\{?env:((?:CHOCK_|CLAUDECODE|AI_AGENT)\w*)\}?\s*[+.]?|\b(CHOCK_\w+|CLAUDECODE|AI_AGENT)\+)=",
            r"\1\2=",
        ),  # $env:X = v, X+=v
        (rf"(?<![\w-])(?:-u\s*|--unset(?:\s+|=)){MARKERS}", r"\1="),  # env -u X, env --unset=X
        (rf"(?<![\w-])export\s+-[a-z]*n[a-z]*(?:\s+[a-z_]\w*)*?\s+{MARKERS}", r"\1="),  # export -n X
        (
            r"(?<![\w./-])env((?:\s+-\S*(?:\s+[^-\s]\S*)?)*?)\s+(?:-[a-z]*i[a-z]*|--ignore-environment|-)(?=\s|$)",
            rf"env\1 {WIPED}=1",  # env -i wipes the markers
        ),
    )
)
PS_REMOVERS = frozenset(("remove-item", "ri", "clear-item", "ci", "rm", "del", "erase"))
FIX = "Fix the failing hook instead; if it must be skipped, ask the person to run the command themselves."
# A line the lexer could not split is refused when it names any of these (CHOCK_ARGV_FALLBACK, fail closed).
FALLBACK = re.compile(
    r"--no-veri|core\.hookspath|\balias\.|include(?:if\.\S*)?\.path|--git-dir|--exec\b|\bforeach\b"
    r"|\bgit\b.*\b(?:commit|am)\b.*\s-[^-\s]*n|commit-tree|update-ref|fast-import|send-pack|\b(?:pre-commit|pre_commit|lefthook|husky)\b.*\buninstall\b"
    r"|\b(?:HUSKY\w*|LEFTHOOK\w*|SKIP|PRE_COMMIT_ALLOW_NO_CONFIG|GIT_DIR|GIT_COMMON_DIR|GIT_CONFIG\w*)\s*=",
    re.IGNORECASE,
)
Verdict = tuple[int, str] | None
TOO_DEEP = "this command nests aliases or scripts too deeply to read; ask the person to run it."
SCRIPT_RUNNERS = frozenset(("fish", "busybox", "iex", "invoke-expression"))  # run a script the lexer does not unwrap
SCRIPT_FLAG = re.compile(r"-[a-z]*c[a-z]*|--command(?:=.*)?", re.DOTALL)
UNREAD = "this line leaves a here-document open, so what it sets for later commands cannot be read; ask the person."


def is_override(name: str) -> bool:
    return OVERRIDE.fullmatch(name) is not None


def assigned(words: list[str]) -> list[str]:
    """Override names written as NAME=value among `words`."""
    return [m.group(1) for w in words if (m := ASSIGN.match(w)) and is_override(m.group(1))]


def set_by(cmd: Cmd, after: Cmd | None) -> list[str]:
    """Names one command sets, blanks or removes: env prefix, env/export (carried in cmd.env), declare, make, set, unset, PowerShell."""
    found = [name for name in cmd.env if is_override(name)]
    args, name = cmd.args, cmd.name
    if name == "git" and WIPED in cmd.env and git_parts(args)[0] in HOOK_SUBS:
        found.append("CLAUDECODE/AI_AGENT (env -i wipes them)")
    if name in DECLARERS:
        found += assigned(args)
    elif name == "unset":
        found += [a for a in args if a.upper() in REMOVAL]
    elif name == "set":
        erasing = any(re.fullmatch(r"-[a-z]*e[a-z]*|--erase", a, re.IGNORECASE) for a in args)
        found += [a for a in args if erasing and a.upper() in REMOVAL] + assigned(args)
        found += [a for a, nxt in pairwise(args) if is_override(a) and not nxt.startswith("-")]
    elif name in ("setx", "setenv"):
        found += [a.split("=", 1)[0] for a in args if is_override(a.split("=", 1)[0])]
    elif name in PS_SETTERS:
        found += [m.group(1) for a in args if (m := PS_PATH.search(a)) and is_override(m.group(1))]
    elif name in PS_REMOVERS:
        found += [m.group(1) for a in args if (m := PS_PATH.search(a)) and m.group(1).upper() in REMOVAL]
    elif name.endswith("setenvironmentvariable") and after is not None:
        found += [w for w in re.split(r"[,\s]+", " ".join([after.name, *after.args])) if is_override(w)]
    return found


def overrides_set(raw: str) -> list[str]:
    """Names the command line sets, blanks or removes. A trailing `true` carries a bare `export X=1` out to a command that shows it."""
    text = raw
    for pattern, repl in REWRITES:
        text = pattern.sub(repl, text)
    cmds = ended(text, "true")
    return [name.upper() for cmd, after in pairwise([*cmds, None]) for name in set_by(cmd, after)]


def ended(text: str, word: str) -> list[Cmd]:
    """The line's commands with `word` run last, so it shows what the line leaves set. A here-document left open
    swallows a next line, so `word` also goes on the last line; [] when neither reaches it."""
    for joined in (f"{text}\n{word}", f"{text} ;{word}"):
        if (cmds := commands(joined)) and cmds[-1].name == word:
            return cmds
    return []


def via(where: str, script: str, found: Verdict) -> Verdict:
    return None if found is None else (found[0], f"{where} runs `{script}`: {found[1]}")


def words_of(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def run_alias(cmd: Cmd, sub: str, rest: list[str], text: str, depth: int) -> Verdict:
    """A call of an alias defined on this line, judged as what it expands to, with the arguments it was given."""
    if text.startswith("!"):
        script = " ".join([*(f"{k}={shlex.quote(v)}" for k, v in cmd.env.items()), text[1:], shlex.join(rest)])
        return via(f"git {sub}", script, check(script, depth + 1))
    prefix = cmd.args[: len(cmd.args) - len(rest) - 1]
    return via(f"git {sub}", f"git {text}", judge_git(cmd._replace(args=[*prefix, *words_of(text), *rest]), depth + 1))


def config_verdicts(pairs: list[tuple[str, str]], env: dict[str, str], depth: int) -> list[Verdict]:
    """core.hooksPath set, or an alias defined, by config this command (or the environment it leaves) carries."""
    found: list[Verdict] = [
        (BLOCK, f"setting core.hooksPath replaces the hooks git runs, so it can switch every one off. {FIX}")
    ]
    found = found if any(key == HOOKS_KEY for key, _ in pairs) else []
    for name, texts in aliases(pairs, env).items():
        for text in texts:
            script = text[1:] if text.startswith("!") else f"git {text}"
            found.append(via(f"git alias {name}", script, check(script, depth + 1)))
    return found


def judge_git(cmd: Cmd, depth: int) -> Verdict:
    """One git command: a hook-skip flag, core.hooksPath, a hook manager's off switch, an alias or script that does so."""
    if depth > DEPTH:
        return ASK, TOO_DEEP
    sub, conf, rest = git_parts(cmd.args)
    pairs = config_pairs(conf, cmd.env) + (config_writes(rest) if sub == "config" else [])
    found = config_verdicts(pairs, cmd.env, depth)
    found += [run_alias(cmd, sub, rest, text, depth) for text in aliases(pairs, cmd.env).get(sub, [])]
    scripts = (rebase_execs(rest) if sub == "rebase" else []) + submodule_scripts(sub, rest)
    found += [via(f"git {sub}", script, check(script, depth + 1)) for script in scripts]
    hooked, hits = sub in HOOK_SUBS, env_hits(cmd.env)
    if hooked and skips_verify(sub, rest):
        found.append((BLOCK, f"git {sub} --no-verify is not allowed. {FIX}"))
    if hooked and hits:
        found.append(
            (BLOCK, f"git {sub} with {hits[0]} switches the hook manager off, exactly as --no-verify does. {FIX}")
        )
    if reason := asks_for(sub, rest, cmd.args, cmd.env, pairs):
        found.append((ASK, reason))
    return strictest(found)


def judge_env(env: dict[str, str], depth: int) -> Verdict:
    """What the line leaves set for the commands after it: a hook manager's off switch, git config, another repo."""
    found = config_verdicts(config_pairs([], env), env, depth)
    if hits := env_hits(env):
        found.append((BLOCK, f"setting {hits[0]} switches the hook manager off for the commands that follow. {FIX}"))
    if reason := env_asks(env):
        found.append((ASK, reason))
    return strictest(found)


def judge(cmd: Cmd, depth: int, kept: dict[str, str]) -> Verdict:
    """One simple command; `kept` gathers what set, declare, setx and Set-Item leave set for the rest of the line."""
    if tool := uninstalls(cmd.name, cmd.args):
        return BLOCK, f"{tool} removes the git hooks it installed, which skips every check they run. {FIX}"
    if inner := launched(cmd.name, cmd.args):
        if inner[0] in SHELLS:  # uv run bash -c '...': the lexer unwraps the shell once it sees it as a command
            return check(shlex.join(inner), depth + 1)
        return judge(cmd._replace(name=inner[0], args=inner[1:]), depth, kept)
    if cmd.name in SCRIPT_RUNNERS:
        at = next((i for i, a in enumerate(cmd.args) if SCRIPT_FLAG.fullmatch(a)), -1)
        script = (
            " ".join([cmd.args[at].partition("=")[2]] if "=" in cmd.args[at] else cmd.args[at + 1 :]) if at >= 0 else ""
        )
        script = script or " ".join(cmd.args)
        return via(cmd.name, script, check(script, depth + 1))
    kept.update(declared(cmd.name, cmd.args))
    env = {**kept, **cmd.env}
    if cmd.name == END:
        return judge_env(env, depth)
    return judge_git(cmd._replace(env=env), depth) if cmd.name == "git" else None


def strictest(found: list[Verdict]) -> Verdict:
    """A block wins over an ask, and either over nothing."""
    return min((verdict for verdict in found if verdict), key=lambda verdict: verdict[0], default=None)


def check(raw: str, depth: int = 0) -> Verdict:
    """(exit code, reason) when a command switches hooks off or sets a person-only override, or None."""
    if depth > DEPTH:
        return ASK, TOO_DEEP
    raw = normalise(raw)
    if named := overrides_set(raw):
        return BLOCK, (
            f"changing {named[0]} is refused: it is a person-only setting (it marks who is committing, answers an ask "
            "gate, or sets the diff limit). Do not set, blank or remove it in any form; ask the person to run the "
            "command themselves with it changed."
        )
    kept: dict[str, str] = {}
    cmds = ended(raw, END)
    found = [judge(cmd, depth, kept) for cmd in cmds or commands(raw)]
    return strictest([*found, None if cmds else (ASK, UNREAD)])


def each_shell(raw: str) -> Verdict:
    """CHOCK_TOOL names the shell when the engine knows it; otherwise the line is read as bash and as PowerShell."""
    tool = os.environ.get("CHOCK_TOOL")
    if (tool or "").lower() in ("bash", "powershell", "pwsh"):
        return check(raw)
    found = []
    for shell in ("bash", "powershell"):
        os.environ["CHOCK_TOOL"] = shell
        found.append(check(raw))
    if tool is None:
        del os.environ["CHOCK_TOOL"]
    else:
        os.environ["CHOCK_TOOL"] = tool
    return strictest(found)


def splits(raw: str) -> bool:
    try:
        shlex.split(normalise(raw), comments=True)
    except ValueError:
        return False
    return True


def unparsed(raw: str) -> Verdict:
    """Fail closed: a line shlex cannot split (the hook sets CHOCK_ARGV_FALLBACK) that names a hook bypass is refused."""
    text = without_bodies(raw)
    fallback = os.environ.get("CHOCK_ARGV_FALLBACK") == "1" or not splits(text)
    if fallback and (hit := FALLBACK.search(text)):
        return (
            BLOCK,
            f"this command does not parse (unbalanced quote or trailing backslash) and names `{hit.group()}`. {FIX}",
        )
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks (the first line is the prompt), 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        raw = os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv)
        verdict = each_shell(raw) or unparsed(raw)
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-no-verify: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if verdict is None:
        return 0
    print(f"BLOCKED: {verdict[1]}" if verdict[0] == BLOCK else verdict[1], file=sys.stderr)
    return verdict[0]


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
