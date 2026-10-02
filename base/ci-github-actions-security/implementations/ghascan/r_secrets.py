"""Pack `secrets`: secrets handed on, dumped, inlined or persisted, and long-lived credentials where OIDC exists."""

from __future__ import annotations

import re

from ghascan import expr
from ghascan.model import (
    IN_EXPR,
    Ctx,
    Hit,
    Step,
    all_env_maps,
    env_maps,
    env_text,
    falsy,
    is_action,
    jobs,
    steps,
    with_text,
    with_values,
)

DEBUG_VARS = frozenset({"ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG"})
WORKSPACE = re.compile(r"^(?:\.|\./|\.git\b.*|\*.*|\./\*.*|\$\{\{\s*github\.workspace\s*\}\}/?)$", re.IGNORECASE)
PUBLISH = (
    (
        "twine upload",
        re.compile(r"\btwine\s+upload\b"),
        ("TWINE_PASSWORD", "TWINE_API_KEY"),
        re.compile(r"\s(?:-p|--password)\b"),
    ),
    ("npm publish", re.compile(r"\bnpm\s+publish\b"), ("NODE_AUTH_TOKEN", "NPM_TOKEN"), None),
    ("cargo publish", re.compile(r"\bcargo\s+publish\b"), ("CARGO_REGISTRY_TOKEN",), re.compile(r"\s--token\b")),
    ("gem push", re.compile(r"\bgem\s+push\b"), ("GEM_HOST_API_KEY",), None),
)


def secrets_inherit(ctx: Ctx) -> list[Hit]:
    hits = []
    for job in jobs(ctx.tree):
        calls = [n.value.strip() for n in ctx.tree.values(("jobs", job, "uses"))]
        external = [c for c in calls if not c.startswith("./")]
        for node in ctx.tree.values(("jobs", job, "secrets")):
            if node.value.strip().lower() == "inherit" and external:
                message = (
                    f"`secrets: inherit` hands every repository and organization secret to {external[0]}, code "
                    "this repository does not review; pass only the secrets that workflow declares"
                )
                hits.append(Hit("gha-secrets-inherit", node.line, job, external[0].split("@")[0].lower(), message))
    return hits


def overprovisioned_secrets(ctx: Ctx) -> list[Hit]:
    """`toJSON(secrets)` or `secrets[<expression>]`: every secret enters the job (zizmor overprovisioned-secrets)."""
    hits = []
    for node in ctx.tree.nodes:
        for path in expr.names(node.value, "secrets"):
            if len(path) == 1 or path[1] == expr.DYNAMIC:
                message = "the whole secrets context (or a computed name in it) reaches this job; name each secret"
                hits.append(Hit("gha-overprovisioned-secrets", node.line, "file", ".".join(path), message))
    return hits


def secret_echo(ctx: Ctx) -> list[Hit]:
    """A secret expanded into script text, or the debug switches that log everything."""
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        for node in ctx.tree.values((*step.path, "run")):
            for path in expr.names(node.value, "secrets"):
                if len(path) > 1 and path[1] not in (expr.DYNAMIC, "github_token"):
                    line = ctx.locate.line("gha-secret-echo", (*step.path, "run"), f"secrets.{path[1]}", mode=IN_EXPR)
                    message = (
                        f"secrets.{path[1].upper()} is pasted into the script text (onto disk, into any log of the "
                        "command line); pass it through `env:` and read the variable"
                    )
                    hits.append(Hit("gha-secret-echo", line, step.job, ".".join(path), message))
    for base in all_env_maps(ctx.tree, ctx.kind):
        for key in ctx.tree.keys(base):
            if str(key).upper() in DEBUG_VARS:
                for node in ctx.tree.values((*base, key)):
                    if not falsy(node.value):
                        message = f"{str(key).upper()} turns on debug logging, which prints values masking can miss"
                        hits.append(Hit("gha-secret-echo", node.line, ".".join(map(str, base)), str(key), message))
    return hits


def _persists(ctx: Ctx, step: Step) -> bool:
    """Whether a checkout leaves its token in .git/config: anything but a literal false that every loader sees."""
    return not falsy(with_text(ctx.tree, step, "persist-credentials"))


def artipacked(ctx: Ctx) -> list[Hit]:
    """A checkout that keeps its token, in a job that uploads the workspace as an artifact (zizmor artipacked)."""
    hits = []
    all_steps = steps(ctx.tree, ctx.kind)
    for job in {s.job for s in all_steps}:
        mine = [s for s in all_steps if s.job == job]
        if not any(is_action(s.uses, "actions/checkout") and _persists(ctx, s) for s in mine):
            continue
        for step in mine:
            if not is_action(step.uses, "actions/upload-artifact"):
                continue
            entries = [e.strip() for v in with_values(ctx.tree, step, "path") for e in v.splitlines() if e.strip()]
            for entry in (e for e in entries if WORKSPACE.match(e)):
                message = (
                    f"uploads `{entry}` from a job whose checkout kept its token in .git/config, so the artifact "
                    "carries the token; set `persist-credentials: false` on the checkout or upload only build output"
                )
                hits.append(Hit("gha-artipacked", ctx.tree.line(step.path), job, entry, message))
    return hits


def checkout_token_pat(ctx: Ctx) -> list[Hit]:
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        if not is_action(step.uses, "actions/checkout") or not _persists(ctx, step):
            continue
        for token in with_values(ctx.tree, step, "token"):
            named = [p for p in expr.names(token, "secrets") if len(p) > 1 and p[1] != "github_token"]
            if named:
                message = (
                    f"checkout stores secrets.{named[0][1].upper()} in .git/config for every later step; set "
                    "`persist-credentials: false` and pass the token only to the step that pushes"
                )
                hits.append(
                    Hit("gha-checkout-token-pat", ctx.tree.line(step.path), step.job, ".".join(named[0]), message)
                )
    return hits


def container_credentials(ctx: Ctx) -> list[Hit]:
    hits = []
    for job in jobs(ctx.tree):
        holders = [("jobs", job, "container")]
        holders += [("jobs", job, "services", s) for s in ctx.tree.keys(("jobs", job, "services"))]
        for base in holders:
            for node in ctx.tree.values((*base, "credentials", "password")):
                if _literal(node.value):
                    where = ".".join(map(str, base[2:]))
                    message = f"{where} credentials hold a literal password; use ${{{{ secrets.NAME }}}}"
                    hits.append(Hit("gha-container-credentials", node.line, job, where, message))
    return hits


STORED = re.compile(r"\$\{\{\s*(?:secrets|vars|inputs)\.[A-Za-z_][A-Za-z0-9_-]*\s*\}\}")


def _literal(text: str) -> bool:
    """Whether a password is anything but one bare `${{ secrets.X }}` (or vars/inputs) reference."""
    return bool(text.strip()) and not STORED.fullmatch(text.strip())


def _from_secret(text: str) -> bool:
    return any(len(p) > 1 for p in expr.names(text, "secrets"))


def trusted_publishing(ctx: Ctx) -> list[Hit]:
    hits = []
    for step in steps(ctx.tree, ctx.kind):
        found = []
        if is_action(step.uses, "pypa/gh-action-pypi-publish") and with_values(ctx.tree, step, "password"):
            found.append("pypa/gh-action-pypi-publish password")
        env = env_text(ctx.tree, env_maps(step) if ctx.kind != "action" else [(*step.path, "env")])
        for label, command, names, flag in PUBLISH:
            run = step.run or ""
            if command.search(run) and (
                any(_from_secret(env.get(n, "")) for n in names) or (flag is not None and flag.search(run))
            ):
                found.append(label)
        for detail in found:
            message = (
                f"publishes with a long-lived token ({detail}); the registry accepts OIDC trusted publishing "
                "(id-token: write), which leaves no token to steal"
            )
            hits.append(Hit("gha-trusted-publishing", ctx.tree.line(step.path), step.job, detail, message))
    return hits


def static_cloud_keys(ctx: Ctx) -> list[Hit]:
    hits = []
    inputs = ctx.tables["cloud_key_inputs"]
    for step in steps(ctx.tree, ctx.kind):
        for action, names in inputs.items():
            if is_action(step.uses, action):
                for name in (n for n in names if with_values(ctx.tree, step, n)):
                    message = f"{action} given a stored key (`{name}`); configure OIDC federation and drop the key"
                    hits.append(
                        Hit("gha-static-cloud-keys", ctx.tree.line(step.path), step.job, f"{action} {name}", message)
                    )
    for base in all_env_maps(ctx.tree, ctx.kind):
        for key in ctx.tree.keys(base):
            if str(key).upper() == "AWS_SECRET_ACCESS_KEY":
                for node in ctx.tree.values((*base, key)):
                    message = "AWS_SECRET_ACCESS_KEY set from a stored key; assume a role through OIDC instead"
                    hits.append(Hit("gha-static-cloud-keys", node.line, ".".join(map(str, base)), str(key), message))
    return hits


RULES = {
    "gha-secrets-inherit": secrets_inherit,
    "gha-overprovisioned-secrets": overprovisioned_secrets,
    "gha-secret-echo": secret_echo,
    "gha-artipacked": artipacked,
    "gha-checkout-token-pat": checkout_token_pat,
    "gha-container-credentials": container_credentials,
    "gha-trusted-publishing": trusted_publishing,
    "gha-static-cloud-keys": static_cloud_keys,
}
