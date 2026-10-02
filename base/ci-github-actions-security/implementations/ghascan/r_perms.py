"""Packs `permissions` and `agents`: what the workflow token may do, and agent steps on outsider text."""

from __future__ import annotations

import re

from ghascan import expr
from ghascan.model import PR_EVENTS, RISKY, WORKFLOW, Ctx, Hit, is_action, job_path, jobs, steps

AGENT_EVENTS = RISKY | {"pull_request_review", "pull_request_review_comment"}
ID_TOKEN_EVENTS = PR_EVENTS | {"issue_comment"}
NULLS = frozenset({"", "~", "null", "Null", "NULL"})
ROLES = frozenset({"owner", "member", "collaborator"})
#: The payload object whose author an agent trigger's text comes from.
OBJECT = {
    "issues": "issue", "issue_comment": "comment", "discussion": "discussion", "discussion_comment": "comment",
    "pull_request_target": "pull_request", "pull_request_review": "review", "pull_request_review_comment": "comment",
    "workflow_run": "workflow_run",
}  # fmt: skip
EQUALS = re.compile(r"github\.event\.([a-z_]+)\.author_association==\'(?:owner|member|collaborator)\'")
LISTED = re.compile(r"contains\(fromjson\(\'(\[[^\]]*\])\'\),github\.event\.([a-z_]+)\.author_association\)")


def _set(ctx: Ctx, path: tuple) -> bool:
    """Whether every loader sees permissions at `path`: a mapping, or a non-empty value (an empty one is null)."""
    nodes = [n for n in ctx.tree.at.get(path, []) if not n.merged]
    return any(n.kind == "map" or n.value.strip() not in NULLS for n in nodes)


def _gated(texts: list[str], on: set[str]) -> bool:
    """Whether the job's and step's conditions admit only OWNER, MEMBER or COLLABORATOR authors of the
    triggering object.

    The conditions are `&&`-joined; each must be one whole expression or a bare one (a mixed or block
    scalar `if:` is always true). Gate terms are whole `&&` terms: `github.event.<object>.author_association
    == '<ROLE>'` or `contains(fromJSON('[<ROLES>]'), github.event.<object>.author_association)`.
    Every object named must be one of the triggers' own (a comment for issue_comment, never the issue)
    and every trigger's object must be named. `||`, `!=`, `!` and backslashes anywhere refuse.
    """
    bodies = []
    for text in texts:
        found = expr.expressions(text)
        if found and (len(found) != 1 or text != text.strip() or not text.startswith("${{") or not text.endswith("}}")):
            return False
        bodies.append(found[0] if found else text)
    flat = re.sub(r"\s+", "", "&&".join(bodies)).replace('"', "'").lower()
    if any(bad in flat for bad in ("||", "!", "\\")):
        return False
    used = set()
    for term in flat.split("&&"):
        if match := EQUALS.fullmatch(term):
            used.add(match.group(1))
        elif match := LISTED.fullmatch(term):
            roles = re.findall(r"'([^']*)'", match.group(1))
            if not roles or not set(roles) <= ROLES:
                return False
            used.add(match.group(2))
    needed = {OBJECT[t] for t in on if t in OBJECT}
    return bool(used) and used == needed


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
        conds = [n.value for n in ctx.tree.values((*job_path(step), "if"))]
        if _gated(conds + [n.value for n in ctx.tree.values((*step.path, "if"))], on):
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
