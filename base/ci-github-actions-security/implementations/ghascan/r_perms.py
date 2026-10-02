"""Packs `permissions` and `agents`: what the workflow token may do, and agent steps on outsider text."""

from __future__ import annotations

import re

from ghascan import expr
from ghascan.model import PR_EVENTS, RISKY, WORKFLOW, Ctx, Hit, conditions, is_action, jobs, steps

AGENT_EVENTS = RISKY | {"pull_request_review", "pull_request_review_comment"}
ID_TOKEN_EVENTS = PR_EVENTS | {"issue_comment"}
NULLS = frozenset({"", "~", "null", "Null", "NULL"})
TRUSTED_ROLES = re.compile(r"OWNER|MEMBER|COLLABORATOR")


def _set(ctx: Ctx, path: tuple) -> bool:
    """Whether every loader sees permissions at `path`: a mapping, or a non-empty value (an empty one is null)."""
    nodes = [n for n in ctx.tree.at.get(path, []) if not n.merged]
    return any(n.kind == "map" or n.value.strip() not in NULLS for n in nodes)


def _gated(text: str) -> bool:
    """Whether a condition restricts the author_association to OWNER, MEMBER or COLLABORATOR: it reads
    one, names one of those roles, and has no `||` or `!=` that could let anyone else through."""
    found = expr.expressions(text) or [text]
    reads = any(p[-1] == "author_association" for e in found for p in expr.contexts(e))
    return reads and bool(TRUSTED_ROLES.search(text)) and "||" not in text and "!=" not in text


def _scalar(ctx: Ctx, path: tuple) -> list[tuple[int, str]]:
    return [(n.line, " ".join(n.value.split()).lower()) for n in ctx.tree.values(path)]


def excessive_permissions(ctx: Ctx) -> list[Hit]:
    """No top-level permissions with a job left on the default token, write-all, or id-token on PR events."""
    if ctx.kind != WORKFLOW:
        return []
    tree = ctx.tree
    hits = []
    reusable_only = ctx.on == {"workflow_call"}
    bare = [j for j in jobs(tree) if not _set(ctx, ("jobs", j, "permissions"))]
    if not _set(ctx, ("permissions",)) and bare and not reusable_only:
        message = (
            f"no top-level `permissions:` and job(s) {', '.join(bare[:5])} set none, so they get the repository's "
            "default token (write to contents and more on older repositories); add `permissions: {}` or "
            "`contents: read` at the top and grant each job only what it needs"
        )
        line = tree.line(("jobs",))
        hits.append(Hit("gha-excessive-permissions", line, "workflow", "no top-level permissions", message))
    holders = [(("permissions",), "workflow")] + [(("jobs", j, "permissions"), j) for j in jobs(tree)]
    for path, scope in holders:
        for line, text in _scalar(ctx, path):
            if text == "write-all":
                message = "`permissions: write-all` hands every scope to every step; list the scopes this needs"
                hits.append(Hit("gha-excessive-permissions", line, scope, "write-all", message))
        on = ctx.on & ID_TOKEN_EVENTS
        for line, text in _scalar(ctx, (*path, "id-token")):
            if text == "write" and on:
                message = (
                    f"`id-token: write` on {', '.join(sorted(on))} lets pull request code mint cloud credentials "
                    "through OIDC; request it only in jobs that run on push or release"
                )
                hits.append(Hit("gha-excessive-permissions", line, scope, "id-token: write", message))
    return hits


def agent_step_untrusted(ctx: Ctx) -> list[Hit]:
    """A coding-agent action run on issue, comment or pull request text with no author-association gate."""
    on = ctx.on & AGENT_EVENTS
    if not on:
        return []
    agents = tuple(ctx.tables["agent_actions"])
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        if not is_action(step.uses, *agents):
            continue
        if _gated(conditions(ctx.tree, step)):
            continue
        name = step.uses.split("@", 1)[0].strip()
        message = (
            f"agent action {name} runs on {', '.join(sorted(on))} text anyone can write, with this workflow's "
            "secrets and token: gate the job on github.event.*.author_association (OWNER, MEMBER, COLLABORATOR) "
            "and give it read-only permissions"
        )
        hits.append(Hit("gha-agent-step-untrusted", ctx.tree.line(step.path), step.job, name.lower(), message))
    return hits


RULES = {
    "gha-excessive-permissions": excessive_permissions,
    "gha-agent-step-untrusted": agent_step_untrusted,
}
