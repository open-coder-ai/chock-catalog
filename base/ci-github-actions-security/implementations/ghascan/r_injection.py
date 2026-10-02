"""Pack `injection`: attacker text expanded into a script, environment-file writes, and the old workflow commands."""

from __future__ import annotations

import re

from ghascan import expr
from ghascan.model import (
    ACTION,
    IN_EXPR,
    RISKY,
    WHOLE_LINE,
    Ctx,
    Hit,
    Step,
    all_env_maps,
    env_maps,
    env_text,
    falsy,
    is_action,
    steps,
)

ENV_FILE = re.compile(r"GITHUB_(?:ENV|PATH)\b")
OLD_COMMAND = re.compile(r"::(?:set-env|add-path)\b", re.IGNORECASE)


def _sinks(ctx: Ctx, step: Step) -> list[tuple[tuple, str]]:
    """(path, text) of each place in a step whose text runs as code: `run`, and github-script's `script`."""
    found = [((*step.path, "run"), n.value) for n in ctx.tree.values((*step.path, "run"))]
    if is_action(step.uses, "actions/github-script"):
        found += [((*step.path, "with", "script"), n.value) for n in ctx.tree.values((*step.path, "with", "script"))]
    return found


def tainted(ctx: Ctx, step: Step) -> frozenset[str]:
    """The `matrix.X` and `env.X` names (lower-cased, as expressions read them) set from attacker text.

    Matrix entries first (an `include` row's keys by name, anything else as `matrix.*`), then env
    values until no new name is found, so `B: ${{ env.A }}` after a tainted A is tainted too.
    """
    found: set[str] = set()
    base = ("jobs", step.job, "strategy", "matrix")
    for node in ctx.tree.under(base) if ctx.kind != ACTION else []:
        if expr.injected(node.value):
            rest = node.path[len(base) :]
            named = rest[2:3] if rest[:1] in (("include",), ("exclude",)) else rest[:1]
            found.add(f"matrix.{str(named[0]).lower()}" if named else "matrix.*")
    maps = [(*step.path, "env")] if ctx.kind == ACTION else env_maps(step)
    env = env_text(ctx.tree, maps)
    grew = True
    while grew:
        grew = False
        for name, text in env.items():
            key = f"env.{name.lower()}"
            if key not in found and expr.injected(text, frozenset(found)):
                found.add(key)
                grew = True
    return frozenset(found)


def template_injection(ctx: Ctx) -> list[Hit]:
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        taint = tainted(ctx, step)
        for path, text in _sinks(ctx, step):
            for found in expr.injected(text, taint, ctx.typed):
                needle = found.split()[0] if found else ""
                line = ctx.locate.line("gha-template-injection", path, needle, mode=IN_EXPR)
                message = (
                    f"`${{{{ {found} }}}}` is expanded into the script before it runs, so whoever writes that "
                    "text writes code: pass it through `env:` and read it as a quoted shell variable"
                )
                hits.append(Hit("gha-template-injection", line, step.job, found, message))
    return hits


def github_env(ctx: Ctx) -> list[Hit]:
    """A write to GITHUB_ENV or GITHUB_PATH in a workflow an outsider can trigger (zizmor github-env)."""
    if not ctx.on & RISKY:
        return []
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        for path, text in _sinks(ctx, step):
            for line_text in text.splitlines():
                match = ENV_FILE.search(line_text)
                if match:
                    line = ctx.locate.line("gha-github-env-injection", path, line_text.strip(), mode=WHOLE_LINE)
                    message = (
                        f"writes {match.group()} under {', '.join(sorted(ctx.on & RISKY))}: a value an outsider "
                        "shapes becomes an environment variable (LD_PRELOAD, BASH_ENV) or a PATH entry for every "
                        "later step; pass it as a step output instead"
                    )
                    hits.append(Hit("gha-github-env-injection", line, step.job, " ".join(line_text.split()), message))
    return hits


def insecure_commands(ctx: Ctx) -> list[Hit]:
    """ACTIONS_ALLOW_UNSECURE_COMMANDS switched on, or the set-env/add-path commands it re-enables."""
    hits = []
    for base in all_env_maps(ctx.tree, ctx.kind):
        for key in ctx.tree.keys(base):
            if str(key).upper() != "ACTIONS_ALLOW_UNSECURE_COMMANDS":
                continue
            for node in ctx.tree.values((*base, key)):
                if not falsy(node.value):
                    message = "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables set-env/add-path from any log line; remove it"
                    hits.append(Hit("gha-insecure-commands", node.line, ".".join(map(str, base)), str(key), message))
    for step in steps(ctx.tree, ctx.kind):
        for path, text in _sinks(ctx, step):
            for match in OLD_COMMAND.finditer(text):
                line = ctx.locate.line("gha-insecure-commands", path, match.group())
                message = f"`{match.group()}` is the removed workflow command; write to the environment file instead"
                hits.append(Hit("gha-insecure-commands", line, step.job, match.group().lower(), message))
    return hits


RULES = {
    "gha-template-injection": template_injection,
    "gha-github-env-injection": github_env,
    "gha-insecure-commands": insecure_commands,
}
