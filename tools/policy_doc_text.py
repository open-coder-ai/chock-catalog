"""The fixed wording of a generated policy page, by mechanism kind."""

CEILING = {
    "gate": "`enforced-at-commit` — the command exits non-zero and the commit does not happen",
    "script": "`enforced-at-commit` — the script exits non-zero and the commit does not happen",
    "guard": (
        "`best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — "
        "the tool call is refused before it runs, on a hook that is actually wired up. "
        "Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; "
        "Cursor's can be told to fail closed, but does not by default"
    ),
    "text": "`advisory` — an agent reads it and may or may not follow it",
}

TOOL_USE_REACH = "; also judged at tool use, `best-effort` once `chock sync` has run (a crashed hook fails open)"

SURFACES = {
    "gate": ["`git-hook`", "`ci-gate`", "`ambient-rule`"],
    "script": ["`git-hook`", "`ambient-rule`"],
    "guard": ["`pre-tool-use`", "`ambient-rule`"],
    "text": ["`ambient-rule`"],
}

PRIMITIVE = {
    "gate": (
        "A **git hook**. `recompile` writes `.chock/compiled/{id}/git-hook/gate.json`, and "
        "`install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is "
        "declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather "
        "than the intent."
    ),
    "script": (
        "A **commit-time guard script**. `recompile` registers `implementations/{script}` under "
        "`.git/hooks/pre-commit.d/`, and the hook runs it at every commit (a commit-msg script gets git's "
        "message file as its one argument, any other none). The script reads the change from git itself "
        "and exits non-zero to refuse; the rule text compiles "
        "to `ambient-rule` beside it, so the agent knows the constraint before the commit is refused."
    ),
    "guard": (
        "A **PreToolUse guard**. `recompile` writes `.chock/compiled/{id}/pre-tool-use/"
        "pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent "
        "consults the guard script before running a Bash command. Until that install runs, the "
        "fragment is compiled and enforces nothing, and coverage says so."
    ),
    "text": (
        "An **ambient rule**. `recompile` writes `.chock/compiled/{id}/ambient-rule/ambient.md`, "
        "and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text "
        "reaches the agent's context and that is the entire mechanism."
    ),
}
