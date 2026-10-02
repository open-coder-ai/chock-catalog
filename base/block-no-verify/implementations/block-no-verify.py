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
    alias_scripts,
    asks_for,
    config_pairs,
    config_writes,
    declared,
    env_hits,
    nested_scripts,
    normalise,
    skips_verify,
    uninstalls,
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
    r"|commit-tree|update-ref|fast-import|\b(?:pre-commit|pre_commit|lefthook|husky)\b.*\buninstall\b"
    r"|\b(?:HUSKY\w*|LEFTHOOK\w*|SKIP|PRE_COMMIT_ALLOW_NO_CONFIG|GIT_DIR|GIT_COMMON_DIR|GIT_CONFIG\w*)\s*=",
    re.IGNORECASE,
)
Verdict = tuple[int, str] | None


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
    cmds = commands(f"{text}\ntrue")
    return [name.upper() for cmd, after in zip(cmds, [*cmds[1:], None], strict=True) for name in set_by(cmd, after)]


def judge_git(cmd: Cmd, depth: int) -> Verdict:
    """One git command: a hook-skip flag, core.hooksPath, a hook manager's off switch, an alias or script that does so."""
    sub, conf, rest = git_parts(cmd.args)
    written = config_writes(rest) if sub == "config" else []
    pairs = config_pairs(conf, cmd.env) + written
    scripts = [(f"git alias {name}", text) for name, text in alias_scripts(pairs, cmd.env)]
    for where, script in scripts + [(f"git {sub}", text) for text in nested_scripts(sub, rest)]:
        if (found := check(script, depth + 1)) is not None:
            return found[0], f"{where} runs `{script}`: {found[1]}"
    hooked, hits = sub in HOOK_SUBS, env_hits(cmd.env)
    blocks = (
        (
            any(key == HOOKS_KEY for key, _ in written),
            "git config core.hooksPath disables every hook, exactly as --no-verify does.",
        ),
        (
            hooked and any(key == HOOKS_KEY for key, _ in pairs),
            f"git {sub} with core.hooksPath set disables every hook, exactly as --no-verify does.",
        ),
        (hooked and skips_verify(sub, rest), f"git {sub} --no-verify is not allowed."),
        (
            hooked and bool(hits),
            f"git {sub} with {''.join(hits[:1])} switches the hook manager off, exactly as --no-verify does.",
        ),
    )
    if reason := next((reason for hit, reason in blocks if hit), ""):
        return BLOCK, f"{reason} {FIX}"
    reason = asks_for(sub, rest, cmd.args, cmd.env, pairs)
    return (ASK, reason) if reason else None


def judge(cmd: Cmd, depth: int) -> Verdict:
    if tool := uninstalls(cmd.name, cmd.args):
        return BLOCK, f"{tool} removes the git hooks it installed, which skips every check they run. {FIX}"
    if hits := declared(cmd.name, cmd.args) or (env_hits(cmd.env) if cmd.name == END else []):
        return BLOCK, f"setting {hits[0]} switches the hook manager off for the commands that follow. {FIX}"
    return judge_git(cmd, depth) if cmd.name == "git" else None


def check(raw: str, depth: int = 0) -> Verdict:
    """(exit code, reason) when a command switches hooks off or sets a person-only override, or None."""
    if depth > DEPTH:
        return ASK, "this command nests aliases or scripts too deeply to read; ask the person to run it."
    if named := overrides_set(raw):
        return BLOCK, (
            f"changing {named[0]} is refused: it is a person-only setting (it marks who is committing, answers an ask "
            "gate, or sets the diff limit). Do not set, blank or remove it in any form; ask the person to run the "
            "command themselves with it changed."
        )
    verdicts = [found for cmd in commands(f"{normalise(raw)}\n{END}") if (found := judge(cmd, depth))]
    return min(verdicts, key=lambda found: found[0], default=None)


def splits(raw: str) -> bool:
    try:
        shlex.split(raw)
    except ValueError:
        return False
    return True


def unparsed(raw: str) -> Verdict:
    """Fail closed: a line shlex cannot split (the hook sets CHOCK_ARGV_FALLBACK) that names a hook bypass is refused."""
    fallback = os.environ.get("CHOCK_ARGV_FALLBACK") == "1" or not splits(raw)
    if fallback and (hit := FALLBACK.search(raw)):
        return (
            BLOCK,
            f"this command does not parse (unbalanced quote or trailing backslash) and names `{hit.group()}`. {FIX}",
        )
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks (the first line is the prompt), 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        raw = os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv)
        verdict = check(raw) or unparsed(raw)
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-no-verify: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if verdict is None:
        return 0
    print(f"BLOCKED: {verdict[1]}" if verdict[0] == BLOCK else verdict[1], file=sys.stderr)
    return verdict[0]


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
