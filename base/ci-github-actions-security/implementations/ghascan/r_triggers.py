"""Pack `triggers`: events an outsider causes, and what a workflow on them checks out, downloads or runs on."""

from __future__ import annotations

import re

from ghascan import expr
from ghascan.model import DANGEROUS, PR_EVENTS, Ctx, Hit, first_line, is_action, normalize, steps, with_values

#: Checkout refs that name the base repository's own code: anything else under a dangerous trigger is
#: treated as the pull request's head, since a step output or an API call can resolve to it too.
BASE_REFS = frozenset(
    {
        ("github", "sha"), ("github", "ref"), ("github", "ref_name"), ("github", "base_ref"),
        ("github", "event", "pull_request", "base", "sha"), ("github", "event", "pull_request", "base", "ref"),
        ("github", "event", "repository", "default_branch"),
    }
)  # fmt: skip
HEAD_RUN = re.compile(
    r"\bgh\s+pr\s+checkout\b|\brefs/pull/|\bpull/[^/\s]+/(?:head|merge)\b"
    r"|\bgit\s+(?:checkout|switch|fetch|pull|reset|worktree)\b[^\n]*\$\{\{[^}\n]*(?:head|workflow_run)",
    re.IGNORECASE,
)
SELF_HOSTED_EVENTS = PR_EVENTS | {"issue_comment"}
REGISTER = re.compile(r"\bconfig\.(?:sh|cmd)\b[^\n]*--token\b", re.IGNORECASE)
BOT_ACTORS = re.compile(
    r"\bgithub\s*\.\s*(?:actor|triggering_actor)\b|\.\s*(?:user|sender)\s*\.\s*login\b", re.IGNORECASE
)


def dangerous_trigger(ctx: Ctx) -> list[Hit]:
    hits = []
    for name in DANGEROUS:
        if name in ctx.on:
            message = (
                f"`{name}` runs this repository's workflow, secrets and write token on an event an outsider "
                "causes; keep untrusted text and code out of it, or use pull_request"
            )
            hits.append(Hit("gha-dangerous-trigger", ctx.tree.line(("on",)), "on", name, message))
    return hits


def _head_ref(text: str) -> bool:
    """Whether a checkout ref (or repository) may name the pull request's head rather than the base."""
    if "pull/" in text.lower():
        return True
    paths = [p for e in expr.expressions(text) for p in expr.contexts(e)]
    return any(p not in BASE_REFS for p in paths)


def prt_head_checkout(ctx: Ctx) -> list[Hit]:
    """pull_request_target, workflow_run or issue_comment checking out the pull request's own code."""
    on = ctx.on & set(DANGEROUS)
    if not on:
        return []
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        found = []
        if is_action(step.uses, "actions/checkout"):
            found = [v for v in with_values(ctx.tree, step, "ref") if _head_ref(v)]
            found += [v for v in with_values(ctx.tree, step, "repository") if expr.expressions(v)]
        found += [m.group() for m in HEAD_RUN.finditer(step.run or "")]
        for detail in found:
            line = first_line(ctx.tree, ctx.lines, step.path, detail.split()[0] if detail.split() else "")
            message = (
                f"checks out pull request code (`{normalize(detail)}`) under {', '.join(sorted(on))}, where it runs "
                "with this repository's secrets and write token; build it in a pull_request workflow instead"
            )
            hits.append(Hit("gha-prt-head-checkout", line, step.job, normalize(detail), message))
    return hits


def _temp_dir(values: list[str]) -> bool:
    return bool(values) and all(re.search(r"runner\s*\.\s*temp|RUNNER_TEMP", v) for v in values)


def workflow_run_artifact(ctx: Ctx) -> list[Hit]:
    """A workflow_run consumer pulling the triggering run's artifacts into its workspace."""
    if "workflow_run" not in ctx.on:
        return []
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        tree = ctx.tree
        detail = ""
        if is_action(step.uses, "actions/download-artifact") and (
            with_values(tree, step, "run-id") or with_values(tree, step, "github-token")
        ):
            detail = "" if _temp_dir(with_values(tree, step, "path")) else "actions/download-artifact"
        elif is_action(step.uses, "dawidd6/action-download-artifact"):
            detail = "" if _temp_dir(with_values(tree, step, "path")) else "dawidd6/action-download-artifact"
        elif is_action(step.uses, "actions/github-script") and "downloadartifact" in " ".join(
            with_values(tree, step, "script")
        ).lower().replace(" ", ""):
            detail = "github-script downloadArtifact"
        for line_text in (step.run or "").splitlines():
            if re.search(r"\bgh\s+run\s+download\b", line_text) and not re.search(
                r"runner\.temp|RUNNER_TEMP", line_text
            ):
                detail = normalize(line_text)
        if detail:
            message = (
                f"workflow_run step downloads the triggering run's artifacts ({detail}) into the workspace, where "
                "a pull request's build can overwrite scripts this job runs; extract to ${{ runner.temp }} and "
                "treat the files as data"
            )
            hits.append(Hit("gha-workflow-run-artifact", tree.line(step.path), step.job, detail, message))
    return hits


def _labels(ctx: Ctx, job: str) -> list[tuple[int, str]]:
    base = ("jobs", job, "runs-on")
    return [(n.line, n.value) for n in ctx.tree.under(base)]


def self_hosted_pr(ctx: Ctx) -> list[Hit]:
    """A self-hosted runner on a trigger a fork can cause, and runner registration in a script."""
    hits = []
    on = ctx.on & SELF_HOSTED_EVENTS
    if on:
        for job in (str(k) for k in ctx.tree.keys(("jobs",))):
            for line, label in _labels(ctx, job):
                if "self-hosted" in label.lower():
                    message = (
                        f"self-hosted runner on {', '.join(sorted(on))}: a pull request runs its code on a machine "
                        "that keeps state between jobs; use a GitHub-hosted or ephemeral runner"
                    )
                    hits.append(Hit("gha-self-hosted-pr", line, job, "self-hosted", message))
    for step in steps(ctx.tree, ctx.kind):
        for match in REGISTER.finditer(step.run or ""):
            line = first_line(ctx.tree, ctx.lines, (*step.path, "run"), match.group().split()[0])
            message = "registers a self-hosted runner from a workflow script; register runners outside CI"
            hits.append(Hit("gha-self-hosted-pr", line, step.job, normalize(match.group()), message))
    return hits


def bot_conditions(ctx: Ctx) -> list[Hit]:
    """An `if:` that trusts an actor's name ending in [bot] (zizmor bot-conditions)."""
    hits = []
    tree = ctx.tree
    conds = [(("jobs", j, "if"), j) for j in (str(k) for k in tree.keys(("jobs",)))]
    conds += [((*s.path, "if"), s.job) for s in steps(tree, ctx.kind)]
    for path, scope in conds:
        for node in tree.values(path):
            bots = [s for e in expr.expressions(node.value) or [node.value] for s in expr.string_literals(e)]
            if BOT_ACTORS.search(node.value) and any(s.lower().endswith("[bot]") for s in bots):
                message = (
                    "condition trusts an actor's name ending in [bot]; github.actor is whoever last acted (a re-run "
                    "or a push to the bot's branch), so compare the pull request author's user id instead"
                )
                hits.append(Hit("gha-bot-conditions", node.line, scope, normalize(node.value), message))
    return hits


RULES = {
    "gha-dangerous-trigger": dangerous_trigger,
    "gha-prt-head-checkout": prt_head_checkout,
    "gha-workflow-run-artifact": workflow_run_artifact,
    "gha-self-hosted-pr": self_hosted_pr,
    "gha-bot-conditions": bot_conditions,
}
