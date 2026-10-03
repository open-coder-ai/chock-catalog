"""Cargo: .cargo/config.toml source replacement, registries, TLS and build redirects; deny.toml sources."""

from __future__ import annotations

from reg_core import CONFUSION, REDIRECT, TLS, Ctx, add, falsy, line_of, norm, secret, url
from reg_parse import toml, walk

#: [build] keys naming a program cargo runs in place of, or around, rustc and rustdoc.
WRAPPERS = frozenset({"rustc", "rustc-wrapper", "rustc-workspace-wrapper", "rustdoc"})


def cargo_config(ctx: Ctx) -> None:
    """.cargo/config.toml: credentials, sources and registries, TLS, and what runs in place of rustc."""
    doc = toml(ctx)
    if doc is None:
        return
    for path, value in walk(doc):
        leaf = path[-1]
        number = line_of(ctx, leaf if not leaf.isdigit() else path[-2])
        if leaf == "token":
            secret(ctx, number, ".".join(path), value)
        elif path[0] in ("source", "registries", "registry", "patch"):
            _source(ctx, number, path, value)
        else:
            _build(ctx, number, path, value)


def _source(ctx: Ctx, number: int, path: tuple[str, ...], value: object) -> None:
    """[source.*], [registries.*], [registry] and [patch.*]: where crates come from."""
    table, leaf, setting = path[0], path[-1], ".".join(path)
    if table == "source" and leaf == "replace-with":
        add(
            ctx,
            REDIRECT,
            number,
            (setting, norm(value)),
            f"{setting} = {norm(value)[:60]} serves crates from another source",
        )
    elif table == "patch":
        url(ctx, number, setting, value, registry=False)
        add(
            ctx,
            REDIRECT,
            number,
            (setting, norm(value)),
            f"[patch] {setting[:80]} replaces a crate with another source",
        )
    elif leaf in ("registry", "index"):
        url(ctx, number, setting, value)
    elif leaf == "git":
        url(ctx, number, setting, value, registry=False)


def _build(ctx: Ctx, number: int, path: tuple[str, ...], value: object) -> None:
    """[http] check-revoke, and the programs and settings that change what a build runs."""
    table, leaf, setting = path[0], path[-1], ".".join(path)
    if table == "http" and leaf == "check-revoke" and falsy(value):
        add(ctx, TLS, number, (setting, "false"), "check-revoke = false skips certificate revocation checks")
    elif (table == "build" and leaf in WRAPPERS) or (table == "target" and path[2:3] in (("runner",), ("linker",))):
        add(ctx, REDIRECT, number, (setting, norm(value)), f"{setting} runs {norm(value)[:60]} in every build")
    elif table in ("alias", "env"):
        add(
            ctx, REDIRECT, number, (setting, norm(value)), f"[{table}] {setting[:80]} changes what cargo builds or runs"
        )


def deny_toml(ctx: Ctx) -> None:
    """cargo-deny: unknown registries or git sources allowed, and the source lists themselves."""
    doc = toml(ctx)
    sources = doc.get("sources") if isinstance(doc, dict) else None
    if not isinstance(sources, dict):
        return
    for path, value in walk(sources, ("sources",)):
        leaf = next(p for p in reversed(path) if not p.isdigit())
        number = line_of(ctx, leaf)
        if leaf in ("unknown-registry", "unknown-git") and norm(value).lower() == "allow":
            add(ctx, CONFUSION, number, (leaf, "allow"), f'{leaf} = "allow" accepts crates from any source')
        elif leaf == "allow-registry":
            # A restriction list, not a fetch source: its default names the crates.io git index on github.com.
            url(ctx, number, leaf, value, registry=False)
        elif leaf == "allow-git":
            url(ctx, number, leaf, value, registry=False)
