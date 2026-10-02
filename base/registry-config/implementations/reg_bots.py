"""Dependabot and Renovate settings that weaken what reaches the repository."""

from __future__ import annotations

import re

from chock_scan.jsonc import JsoncError, loads
from reg_core import COOLDOWN, SCRIPTS, VCS, Ctx, add, line_of, norm, secret, truthy, url, urls_in
from reg_parse import json_doc, walk, yaml_scalars

BOT_SECRETS = frozenset({"token", "password", "key"})
#: A JSON5 credential written out: token: '...', "password": "...".
JSON5_SECRET = re.compile(r"""\b(token|password)["']?\s*:\s*["']([^"']*)["']""")


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
    """renovate.json(5) / .renovaterc: postUpgradeTasks, automerge, registryUrls, hostRules secrets.

    JSON5 that the JSON-with-comments reader refuses (unquoted keys, single quotes) is read line by line."""
    if ctx.path.lower().endswith(".json5"):
        try:
            doc = loads(ctx.text).value
        except JsoncError:
            _renovate_lines(ctx)
            return
    else:
        doc = json_doc(ctx)
    for path, value in walk(doc):
        if "encrypted" in path:
            # Renovate's encrypted secrets are made to be committed: only the app's private key opens them.
            continue
        named = [p for p in path if not p.isdigit()]
        leaf = named[-1] if named else ""
        number = line_of(ctx, leaf)
        if "postupgradetasks" in named and leaf == "commands":
            add(
                ctx,
                SCRIPTS,
                number,
                ("postUpgradeTasks", norm(value)),
                "postUpgradeTasks runs commands on every update",
            )
        elif leaf == "automerge" and truthy(value):
            add(ctx, VCS, number, (".".join(named), "true"), "automerge merges updates without a person's review")
        elif "registryurls" in named:
            url(ctx, number, "registryUrls", value)
        elif "hostrules" in named and leaf in BOT_SECRETS:
            secret(ctx, number, ".".join(named), value)


def _renovate_lines(ctx: Ctx) -> None:
    """A line-wise read: a registryUrls list is judged from its key up to the line closing it."""
    listing = False
    for number, line in enumerate(ctx.lines, 1):
        if line.lstrip().startswith("//"):
            continue
        if re.search(r"\bpostUpgradeTasks\b", line):
            add(ctx, SCRIPTS, number, ("postUpgradeTasks", "json5"), "postUpgradeTasks runs commands on every update")
        if re.search(r"""\bautomerge["']?\s*:\s*true\b""", line):
            add(ctx, VCS, number, ("automerge", "true"), "automerge merges updates without a person's review")
        for match in () if "encrypted" in line else JSON5_SECRET.finditer(line):
            secret(ctx, number, f"hostRules.{match[1]}", match[2])
        listing = listing or re.search(r"\bregistryUrls\b", line) is not None
        if listing:
            urls_in(ctx, number, "registryUrls", line)
            listing = "]" not in line
