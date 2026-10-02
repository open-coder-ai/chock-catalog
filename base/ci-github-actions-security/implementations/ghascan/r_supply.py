"""Pack `supply`: caches restored into release builds, and Dependabot settings that run or skip updates unchecked."""

from __future__ import annotations

import re

from ghascan.model import Ctx, Hit, Step, falsy, is_action, steps, with_text, with_values

PUBLISH_RUN = re.compile(
    r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b|\bdocker\s+push\b"
    r"|\bgoreleaser\b|\bgh\s+release\s+(?:create|upload)\b|\bpoetry\s+publish\b|\buv\s+publish\b"
    r"|\bsemantic-release\b|\bchangeset\s+publish\b"
)


def _restores_cache(ctx: Ctx, step: Step) -> str:
    """What restores a cache in this step, or ''."""
    tables = ctx.tables
    if is_action(step.uses, *tables["cache_actions"]) and not is_action(step.uses, "actions/cache/save"):
        return step.uses.split("@")[0].strip().lower()
    if is_action(step.uses, *tables["cache_default_on"]):
        return "" if falsy(with_text(ctx.tree, step, "cache")) else step.uses.split("@")[0].strip().lower() + " cache"
    if is_action(step.uses, *tables["cache_input_actions"]):
        given = [v for v in with_values(ctx.tree, step, "cache") if not falsy(v)]
        return step.uses.split("@")[0].strip().lower() + " cache" if given else ""
    if is_action(step.uses, "docker/build-push-action") and with_values(ctx.tree, step, "cache-from"):
        return "docker/build-push-action cache-from"
    return ""


def _publishes(ctx: Ctx, step: Step) -> bool:
    return is_action(step.uses, *ctx.tables["publish_actions"]) or bool(PUBLISH_RUN.search(step.run or ""))


def cache_poisoning(ctx: Ctx) -> list[Hit]:
    """A cache restored in a release workflow, or in a job that publishes (zizmor cache-poisoning)."""
    tags = ctx.tree.has(("on", "push", "tags")) or ctx.tree.has(("on", "push", "tags-ignore"))
    release = "release" in ctx.on or tags
    all_steps = steps(ctx.tree, ctx.kind)
    publishing = {s.job for s in all_steps if _publishes(ctx, s)}
    hits = []
    for step in all_steps:
        what = _restores_cache(ctx, step)
        if what and (release or step.job in publishing):
            why = "a release workflow" if release else "a job that publishes"
            message = (
                f"{what} restores a cache in {why}: any pull request or branch that can write that cache key "
                "shapes the release; build releases without caches"
            )
            hits.append(Hit("gha-cache-poisoning", ctx.tree.line(step.path), step.job, what, message))
    return hits


def dependabot_weaken(ctx: Ctx) -> list[Hit]:
    """insecure-external-code-execution allowed, a blanket ignore, or an update entry without a cooldown."""
    tree = ctx.tree
    hits = []
    for node in tree.nodes:
        if node.path and node.path[-1] == "insecure-external-code-execution" and node.value.strip().lower() == "allow":
            message = "insecure-external-code-execution: allow runs dependency code during the update; remove it"
            hits.append(Hit("gha-dependabot-weaken", node.line, "updates", "insecure-external-code-execution", message))
    for index in tree.keys(("updates",)):
        entry = ("updates", index)
        ecosystem = (tree.text((*entry, "package-ecosystem")) or "").strip()
        scope = f"{ecosystem} {(tree.text((*entry, 'directory')) or '').strip()}".strip()
        for item in tree.keys((*entry, "ignore")):
            rule = (*entry, "ignore", item)
            names = [n.value.strip() for n in tree.values((*rule, "dependency-name"))]
            narrowed = tree.has((*rule, "versions")) or tree.has((*rule, "update-types"))
            if any(n and set(n) == {"*"} for n in names) and not narrowed:
                message = (
                    f"ignore `*` with no versions or update-types stops every {ecosystem} update, security fixes too"
                )
                hits.append(Hit("gha-dependabot-weaken", tree.line(rule), scope, "ignore *", message))
        if not tree.has((*entry, "cooldown"), trusted=True):
            message = (
                f"{scope or 'this update entry'} has no `cooldown:`, so a release published minutes ago (before "
                "anyone notices it is compromised) is proposed at once; add cooldown default-days"
            )
            hits.append(Hit("gha-dependabot-cooldown", tree.line(entry), scope, "no cooldown", message))
    return hits


RULES = {
    "gha-cache-poisoning": cache_poisoning,
    "gha-dependabot-weaken": dependabot_weaken,
}
