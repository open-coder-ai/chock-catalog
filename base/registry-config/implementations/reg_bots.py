"""Dependabot and Renovate settings that weaken what reaches the repository."""

from __future__ import annotations

from reg_core import COOLDOWN, SCRIPTS, VCS, Ctx, add, line_of, norm, secret, truthy, url
from reg_json5 import Json5Error, to_jsonc
from reg_parse import json_doc, refuse, walk, yaml_scalars

BOT_SECRETS = frozenset({"token", "password", "key"})


def dependabot(ctx: Ctx) -> None:
    """dependabot.yml: external code execution, registries, blanket ignores, updates with no cooldown."""
    nodes = yaml_scalars(ctx)
    if nodes is None:
        return
    updates: dict[str, list[str]] = {}
    cooled: set[str] = set()
    # A registry of type git names a repository host (github.com), not a package index: clear text only.
    gits = {
        path[1] for path, value, _ in nodes if path[:1] == ("registries",) and path[2:] == ("type",) and value == "git"
    }
    for path, value, number in nodes:
        head, setting = path[:2], path[2:3]
        if head[:1] == ("registries",) and setting:
            _registry(ctx, number, path, value, index=path[1] not in gits)
        elif head[:1] == ("updates",) and setting:
            entry = updates.setdefault(path[1], [str(number), "", ""])
            if path[2:] in (("package-ecosystem",), ("directory",)):
                entry[1 if path[2] == "package-ecosystem" else 2] = norm(value)
            elif setting == ("cooldown",):
                cooled.add(path[1])
            else:
                _update_setting(ctx, number, path, value)
    for index, (number, ecosystem, directory) in updates.items():
        if index not in cooled:
            add(
                ctx,
                COOLDOWN,
                int(number),
                ("updates", f"{ecosystem}|{directory}"),
                f"{ecosystem or 'an update'} has no cooldown",
            )


def _registry(ctx: Ctx, number: int, path: tuple[str, ...], value: str, *, index: bool) -> None:
    if path[2:] == ("url",):
        url(ctx, number, ".".join(path), value, registry=index)
    elif path[2:] in {(name,) for name in BOT_SECRETS}:
        secret(ctx, number, ".".join(path), value)


def _update_setting(ctx: Ctx, number: int, path: tuple[str, ...], value: str) -> None:
    leaf = path[2]
    if leaf == "insecure-external-code-execution" and norm(value).lower() == "allow":
        message = "insecure-external-code-execution: allow runs dependency code during updates"
        add(ctx, SCRIPTS, number, (leaf, "allow"), message)
    elif leaf == "ignore" and path[-1] == "dependency-name" and norm(value) == "*":
        message = "an ignore for dependency-name '*' stops every update, security fixes included"
        add(ctx, VCS, number, ("ignore", "*"), message)


def renovate(ctx: Ctx) -> None:
    """renovate.json(5) / .renovaterc: postUpgradeTasks, automerge, registryUrls, written-out credentials.
    JSON5 is turned into JSON with comments first; what still does not parse is refused."""
    if ctx.path.lower().endswith(".json5"):
        try:
            ctx = Ctx(ctx.path, to_jsonc(ctx.text), ctx.allow, ctx.out)
        except Json5Error as exc:
            refuse(ctx, "JSON5 file", exc)
            return
    for path, value in walk(json_doc(ctx)):
        if "encrypted" in path:
            # Renovate's encrypted secrets are made to be committed: only the app's private key opens them.
            continue
        named = [p for p in path if not p.isdigit()]
        leaf = named[-1] if named else ""
        number = line_of(ctx, leaf)
        if "postupgradetasks" in named and leaf == "commands":
            message = "postUpgradeTasks runs commands on every update"
            add(ctx, SCRIPTS, number, ("postUpgradeTasks", norm(value)), message)
        elif leaf == "automerge" and truthy(value):
            add(ctx, VCS, number, (".".join(named), "true"), "automerge merges updates without a person's review")
        elif "registryurls" in named:
            url(ctx, number, "registryUrls", value)
        elif leaf == "npmtoken" or ("hostrules" in named and leaf in BOT_SECRETS):
            secret(ctx, number, ".".join(named), value)
