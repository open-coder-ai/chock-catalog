"""Pack `hygiene`: conditions that are always true, weakened security steps, obfuscation, unchecked auto-merge."""

from __future__ import annotations

import re

from ghascan import expr
from ghascan.model import WHOLE_LINE, Ctx, Hit, Step, falsy, is_action, job_path, jobs, normalize, steps

SECURITY_WORDS = re.compile(
    r"\b(?:codeql|semgrep|trivy|grype|snyk|zizmor|actionlint|gitleaks|trufflehog|bandit|gosec|osv-scanner|scorecard"
    r"|pip-audit|audit|sast|dast|scan|scanner|lint|pytest|jest|vitest|mocha|rspec|phpunit|chock|verify|sbom|attest"
    r"|(?:npm|pnpm|yarn|go|cargo|make|mvn|gradle|dotnet|bun|deno)\s+(?:run\s+)?test)\b",
    re.IGNORECASE,
)
SWALLOW = re.compile(r"\|\|\s*(?:true|:|exit\s+0)\b|;\s*(?:true|exit\s+0)\s*$")
AUTO_MERGE = re.compile(r"\bgh\s+pr\s+merge\b[^\n]*--(?:auto|admin)\b|\bgh\s+pr\s+review\b[^\n]*(?:--approve|\s-a\b)")
ODD_USES = re.compile(r"\$\{\{|(?:^|/)\.\.(?:/|$)|\s|['\"\\]|//")


def _if_paths(ctx: Ctx) -> list[tuple[tuple, str]]:
    found = [(("jobs", j, "if"), j) for j in jobs(ctx.tree)]
    return found + [((*s.path, "if"), s.job) for s in steps(ctx.tree, ctx.kind)]


def unsound_condition(ctx: Ctx) -> list[Hit]:
    """An `if:` that is a non-empty string whatever it says, or contains() on a literal string."""
    hits = []
    for path, scope in _if_paths(ctx):
        for node in ctx.tree.values(path):
            text = node.value
            found = expr.expressions(text)
            whole = text.strip().startswith("${{") and text.strip().endswith("}}") and len(found) == 1
            if found and (not whole or text != text.strip()):
                message = (
                    "this `if:` mixes `${{ }}` with other text (or a block scalar's newline), so it is a non-empty "
                    "string and always true; write the whole condition inside one `${{ }}`, or none"
                )
                hits.append(Hit("gha-unsound-condition", node.line, scope, normalize(text), message))
            for body in found or [text]:
                toks = expr.tokens(body)
                for i, (kind, word) in enumerate(toks[:-2]):
                    if (
                        kind == "id"
                        and word.lower() == "contains"
                        and toks[i + 1][1] == "("
                        and toks[i + 2][0] == "str"
                    ):
                        message = (
                            "contains() on a literal string tests for a substring, so 'refs/heads/main' matches a "
                            "branch named 'main' or 'ma'; compare with == or use fromJSON('[...]')"
                        )
                        hits.append(Hit("gha-unsound-condition", node.line, scope, normalize(body), message))
    return hits


def _step_words(ctx: Ctx, step: Step) -> str:
    name = " ".join(n.value for n in ctx.tree.values((*step.path, "name")))
    return f"{step.uses} {name} {step.run or ''}"


def security_step_weakened(ctx: Ctx) -> list[Hit]:
    """continue-on-error, `|| true` or a constant false `if:` on a scan, audit, lint or test step."""
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        words = _step_words(ctx, step)
        if not SECURITY_WORDS.search(words):
            continue
        what = SECURITY_WORDS.search(words).group().lower()
        for node in ctx.tree.values((*step.path, "continue-on-error")):
            if not falsy(node.value):
                message = f"continue-on-error on a {what} step turns its failure into a pass; let it fail"
                hits.append(
                    Hit("gha-security-step-weakened", node.line, step.job, f"{what} continue-on-error", message)
                )
        for node in ctx.tree.values((*step.path, "if")):
            if normalize(node.value).lower() in ("false", "${{ false }}", "${{false}}"):
                message = f"`if: false` switches off a {what} step; delete it in review or keep it running"
                hits.append(Hit("gha-security-step-weakened", node.line, step.job, f"{what} if false", message))
        for line_text in (step.run or "").splitlines():
            if SECURITY_WORDS.search(line_text) and SWALLOW.search(line_text):
                line = ctx.locate.line(
                    "gha-security-step-weakened", (*step.path, "run"), line_text.strip(), mode=WHOLE_LINE
                )
                message = f"`{SWALLOW.search(line_text).group().strip()}` hides the {what} command's failure"
                hits.append(Hit("gha-security-step-weakened", line, step.job, normalize(line_text), message))
    return hits


def obfuscation(ctx: Ctx) -> list[Hit]:
    """`uses:` built from an expression or with odd paths, `shell: cmd`, and expressions that are only a literal."""
    hits = []
    tree = ctx.tree
    for step in steps(tree, ctx.kind):
        for node in tree.values((*step.path, "uses")):
            name = node.value.strip().removeprefix("docker://")
            if ODD_USES.search(name.removeprefix("./")):
                message = "`uses:` with an expression, `..`, spaces or quotes hides what runs; name the action plainly"
                hits.append(Hit("gha-obfuscation", node.line, step.job, normalize(node.value), message))
        for node in tree.values((*step.path, "shell")):
            if node.value.strip().lower() == "cmd":
                message = "`shell: cmd` has quoting no reviewer reads reliably; use pwsh or bash"
                hits.append(Hit("gha-obfuscation", node.line, step.job, "shell: cmd", message))
    for node in tree.nodes:
        for body in expr.expressions(node.value):
            toks = expr.tokens(body)
            if len(toks) == 1 and toks[0][0] == "str":
                message = f"`${{{{ {normalize(body)} }}}}` is a literal dressed as an expression; write the text"
                hits.append(Hit("gha-obfuscation", node.line, "file", normalize(body), message))
    return hits


def auto_merge_bot(ctx: Ctx) -> list[Hit]:
    """Auto-merge or auto-approve in a job that never checks the update type (dependabot/fetch-metadata)."""
    hits = []
    all_steps = steps(ctx.tree, ctx.kind)
    for step in all_steps:
        found = [m.group() for m in AUTO_MERGE.finditer(step.run or "")]
        if is_action(step.uses, *ctx.tables["automerge_actions"]):
            found.append(step.uses.split("@")[0].strip().lower())
        if not found:
            continue
        job_text = " ".join(n.value for n in ctx.tree.under(job_path(step)))
        if "update-type" in job_text or "update_type" in job_text:
            continue
        for detail in found:
            message = (
                f"`{normalize(detail)}` merges or approves without checking the update type; gate it on "
                "dependabot/fetch-metadata's update-type (patch, minor) and the pull request author's id"
            )
            hits.append(Hit("gha-auto-merge-bot", ctx.tree.line(step.path), step.job, normalize(detail), message))
    return hits


RULES = {
    "gha-unsound-condition": unsound_condition,
    "gha-security-step-weakened": security_step_weakened,
    "gha-obfuscation": obfuscation,
    "gha-auto-merge-bot": auto_merge_bot,
}
