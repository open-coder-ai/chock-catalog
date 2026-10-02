"""npm, Yarn (classic and Berry), pnpm and Bun registry settings."""

from __future__ import annotations

import re

from reg_core import (
    COOLDOWN,
    REDIRECT,
    SCRIPTS,
    TLS,
    Ctx,
    add,
    digest,
    falsy,
    line_of,
    norm,
    secret,
    truthy,
    url,
)
from reg_parse import ini_pairs, toml, unquote, walk, yaml_scalars

#: npm and pnpm credential keys, after any '//host/:' prefix.
NPM_SECRETS = frozenset({"_authtoken", "_auth", "_password", "password", "token"})
#: A version spec that is not a version: an alias, a link, a path, a git or tarball URL.
EXOTIC = re.compile(
    r"^(?:(?:npm|link|file|portal|patch|git|git\+[a-z]+|github|gitlab|bitbucket|https?|workspace):"
    r"|[\w.-]+/[\w.-]+(?:#.*)?$|[\w.-]+@[\w.-]+:)",
    re.IGNORECASE,
)
NPM_COOLDOWN = ("min-release-age", "minimum-release-age")
#: A Yarn classic line: `key value`, `"key" "value"` or `key: value` (its parser takes an optional colon).
YARN_V1 = re.compile(r'^\s*("(?:[^"\\]|\\.)*"|[^\s:"]+(?::[^\s:"]+)*)(?:\s+|\s*:\s*)(.*?)\s*$')
#: A release age of zero is no cooldown at all.
AGE = re.compile(r"^\s*([0-9]+(?:\.[0-9]*)?)\s*[a-z]*\s*$")


def has_age(value: object) -> bool:
    """A release age above zero (a number, optionally with a unit); anything else is no cooldown."""
    match = AGE.match(norm(value).lower())
    return bool(match) and float(match[1]) > 0


def _scripts_on(ctx: Ctx, key: str, value: str, number: int) -> bool:
    """npm and pnpm switches (kebab or camel case) that let dependencies run code at install."""
    flat = key.replace("-", "").replace("_", "")
    bad = (
        (flat == "ignorescripts" and falsy(value))
        or flat == "scriptshell"
        or (flat == "unsafeperm" and truthy(value))
        or (flat == "dangerouslyallowallbuilds" and truthy(value))
        or (flat in ("strictdepbuilds", "blockexoticsubdeps") and falsy(value))
        or (flat == "trustpolicy" and norm(value).lower() == "off")
        or (flat.startswith("onlybuiltdependencies") and "*" in value)
    )
    if bad:
        add(
            ctx,
            SCRIPTS,
            number,
            (flat, norm(value).lower()),
            f"{key} = {norm(value)[:60]} lets dependencies run install scripts",
        )
    return bad


def npmrc(ctx: Ctx) -> None:
    """.npmrc (npm, pnpm): tokens, registries, strict-ssl, script switches, pnpmfile, release-age cooldown."""
    cooled = False
    for _, key, value, number in ini_pairs(ctx):
        name = key.rsplit(":", 1)[-1] if key.startswith("//") else key
        if name in NPM_SECRETS:
            secret(ctx, number, key, value)
        elif name == "registry" or name.endswith(":registry"):
            url(ctx, number, key, value)
        elif name == "strict-ssl" and falsy(value):
            add(ctx, TLS, number, (name, "false"), "strict-ssl=false turns TLS verification off")
        elif "pnpmfile" in name:
            add(ctx, REDIRECT, number, (name, norm(value)), f"{name} runs a hook that can rewrite every package")
        elif name in NPM_COOLDOWN:
            cooled = has_age(value)
        else:
            _scripts_on(ctx, name, value, number)
    if not cooled:
        add(ctx, COOLDOWN, 1, ("npmrc", ""), "no min-release-age: a version published minutes ago installs at once")


def yarnrc(ctx: Ctx) -> None:
    """.yarnrc (Yarn classic): `key value` lines."""
    for number, raw in enumerate(ctx.lines, 1):
        match = YARN_V1.match(raw)
        if not match or raw.lstrip().startswith("#"):
            continue
        key, value = unquote(match[1]).lower().lstrip("-"), unquote(match[2])
        if key == "registry" or key.endswith(":registry"):
            url(ctx, number, key, value)
        elif key == "strict-ssl" and falsy(value):
            add(ctx, TLS, number, (key, "false"), "strict-ssl false turns TLS verification off")
        elif key == "yarn-path":
            add(ctx, REDIRECT, number, (key, norm(value)), "yarn-path runs another Yarn binary for every command")
        elif key.rsplit(":", 1)[-1] in NPM_SECRETS:
            secret(ctx, number, key, value)
        else:
            _scripts_on(ctx, key, value, number)


def yarnrc_yml(ctx: Ctx) -> None:
    """.yarnrc.yml (Yarn Berry)."""
    nodes = yaml_scalars(ctx)
    if nodes is None:
        return
    cooled = False
    for path, value, number in nodes:
        leaf = path[-1] if path else ""
        if leaf in ("npmregistryserver", "npmpublishregistry"):
            url(ctx, number, ".".join(path), value)
        elif leaf in ("npmauthtoken", "npmauthident"):
            secret(ctx, number, ".".join(path), value)
        elif path == ("npmminimalagegate",):
            cooled = has_age(value)
        else:
            _berry_setting(ctx, number, path, value)
    if not cooled:
        add(ctx, COOLDOWN, 1, ("yarnrc", ""), "no npmMinimalAgeGate: a version published minutes ago installs at once")


def _berry_setting(ctx: Ctx, number: int, path: tuple[str, ...], value: str) -> None:
    """Yarn Berry's TLS, script and loader settings."""
    leaf, listed = (path[-1] if path else ""), bool(path[1:])
    if leaf == "enablestrictssl" and falsy(value):
        add(ctx, TLS, number, (leaf, "false"), "enableStrictSsl: false turns TLS verification off")
    elif path[:1] == ("unsafehttpwhitelist",) and listed:
        add(ctx, TLS, number, (path[0], norm(value)), f"unsafeHttpWhitelist lets {norm(value)[:60]} serve over http")
    elif leaf == "enablescripts" and truthy(value):
        add(ctx, SCRIPTS, number, (leaf, "true"), "enableScripts: true lets dependencies run install scripts")
    elif path == ("yarnpath",) or (path[:1] == ("plugins",) and listed and value):
        add(ctx, REDIRECT, number, (path[0], norm(value)), f"{path[0]} runs code Yarn loads for every command")


def pnpm_workspace(ctx: Ctx) -> None:
    """pnpm-workspace.yaml: settings in camel case, overrides, release-age cooldown."""
    nodes = yaml_scalars(ctx)
    if nodes is None:
        return
    cooled = False
    for path, value, number in nodes:
        top = path[0] if path else ""
        if top == "registry" or (top == "registries" and path[1:] and not path[2:]):
            url(ctx, number, ".".join(path), value)
        elif top == "strictssl" and falsy(value):
            add(ctx, TLS, number, (top, "false"), "strictSsl: false turns TLS verification off")
        elif top in ("pnpmfile", "globalpnpmfile") and value:
            add(ctx, REDIRECT, number, (top, norm(value)), f"{top} runs a hook that can rewrite every package")
        elif top in ("overrides", "catalog", "catalogs") and EXOTIC.match(norm(value)):
            add(
                ctx,
                REDIRECT,
                number,
                (".".join(path), norm(value)),
                f"{'.'.join(path)[:80]} resolves to {norm(value)[:80]}",
            )
        elif top == "minimumreleaseage":
            cooled = has_age(value)
        elif not path[2:]:
            _scripts_on(ctx, top, value, number)
    if not cooled:
        add(ctx, COOLDOWN, 1, ("pnpm", ""), "no minimumReleaseAge: a version published minutes ago installs at once")


def pnpmfile(ctx: Ctx) -> None:
    """.pnpmfile.cjs, and Yarn's committed releases and plugins: code the package manager runs on every
    install; any new or changed content asks, keyed by its digest (read whatever its size)."""
    add(
        ctx,
        REDIRECT,
        1,
        ("loaded code", digest(ctx.text)),
        "this file is code the package manager runs on every install",
    )


def bunfig(ctx: Ctx) -> None:
    """bunfig.toml: [install] registry and scopes (string or table), credentials, release-age cooldown."""
    doc = toml(ctx)
    if doc is None:
        return
    install = doc.get("install")
    if not isinstance(install, dict):
        return
    for path, value in walk(install, ("install",)):
        setting = ".".join(path)
        number = line_of(ctx, path[-1] if not path[-1].isdigit() else path[-2])
        if path[-1] in ("token", "password"):
            secret(ctx, number, setting, value)
        elif path[1:2] in (("registry",), ("scopes",)) and (
            path[-1] in ("registry", "url") or (path[1] == "scopes" and not path[3:])
        ):
            url(ctx, number, setting, value)
    ages = {str(k).lower(): v for k, v in install.items()}
    if not has_age(ages.get("minimumreleaseage", "")):
        add(
            ctx,
            COOLDOWN,
            line_of(ctx, "[install"),
            ("bunfig", ""),
            "no minimumReleaseAge: a new version installs at once",
        )
