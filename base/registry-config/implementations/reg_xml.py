"""NuGet (nuget.config, Directory.Build.props, project files) and Maven settings.xml, from one linear token pass."""

from __future__ import annotations

import re

from reg_core import CONFUSION, TLS, Ctx, add, norm, secret, truthy, url
from reg_parse import refuse
from reg_xmltok import Token, XmlError, element_texts, tokens

#: Credential keys NuGet reads from packageSourceCredentials and from <config>.
NUGET_SECRETS = frozenset({"cleartextpassword", "password", "http_proxy.password"})
RESTORE = frozenset({"restoresources", "restoreadditionalprojectsources"})
MAVEN_SECRETS = frozenset({"password", "passphrase"})
#: A Maven password encrypted with the master password ({...}): not readable from the file alone.
MAVEN_ENCRYPTED = re.compile(r"^\{[A-Za-z0-9+/=]+\}$")


def _read(ctx: Ctx) -> list[Token] | None:
    try:
        return tokens(ctx.text)
    except XmlError as exc:
        refuse(ctx, "XML file", exc)
        return None


def nuget(ctx: Ctx) -> None:
    found = _read(ctx)
    if found is None:
        return
    adds, cleared, sections = _package_sources(found)
    for token in adds:
        _source(ctx, token)
    mapped = any(t.name == "packagesourcemapping" for t in found)
    if adds and (not cleared or (len(adds) > 1 and not mapped)):
        why = (
            "no <clear/>: sources from user and machine configs also resolve"
            if not cleared
            else "no packageSourceMapping"
        )
        message = f"{why}, so a name may come from any source"
        add(ctx, CONFUSION, ctx.line_at(sections[0]), ("packageSources", f"{cleared}|{mapped}"), message)
    for token in found:
        if token.name == "add" and token.kind in ("start", "empty"):
            _setting(ctx, token)


def _package_sources(found: list[Token]) -> tuple[list[Token], bool, list[int]]:
    """The <add> sources inside every <packageSources>, whether one holds a <clear/>, and where each opens."""
    depth, inner, adds, cleared, sections = 0, 0, [], False, []
    for token in found:
        if token.name == "packagesources" and token.kind != "text":
            depth = max(depth + {"start": 1, "end": -1}.get(token.kind, 0), 0)
            sections += [token.pos] if token.kind != "end" else []
            inner = 0
        elif depth and token.kind in ("start", "empty"):
            # Every <add> is judged wherever it sits; only a <clear/> directly in packageSources clears.
            adds += [token] if token.name == "add" else []
            cleared = cleared or (token.name == "clear" and not inner)
            inner += token.kind == "start"
        elif depth and token.kind == "end":
            inner = max(inner - 1, 0)
    return adds, cleared, sections


def _source(ctx: Ctx, token: Token) -> None:
    number = ctx.line_at(token.pos)
    url(ctx, number, f"packageSources.{token.attrs.get('key', '')}", token.attrs.get("value", ""))
    if truthy(token.attrs.get("allowinsecureconnections", "")):
        message = "allowInsecureConnections lets a source serve over http"
        add(ctx, TLS, number, ("allowInsecureConnections", token.attrs.get("key", "")), message)


def _setting(ctx: Ctx, token: Token) -> None:
    key = token.attrs.get("key", "").lower()
    number = ctx.line_at(token.pos)
    if key in NUGET_SECRETS:
        secret(ctx, number, key, token.attrs.get("value", ""))
    elif key == "signaturevalidationmode" and norm(token.attrs.get("value", "")).lower() == "accept":
        add(ctx, TLS, number, (key, "accept"), "signatureValidationMode accept installs unsigned packages")


def props(ctx: Ctx) -> None:
    """Directory.Build.props and project files: RestoreSources and RestoreAdditionalProjectSources, ';'-separated."""
    found = _read(ctx)
    for name, text, pos in element_texts(found or [], RESTORE):
        for item in text.split(";"):
            url(ctx, ctx.line_at(pos), name, item.strip())


def maven(ctx: Ctx) -> None:
    """Maven settings.xml: mirror and repository URLs, written-out server passwords."""
    if "<settings" not in ctx.text:
        return
    found = _read(ctx)
    for name, text, pos in element_texts(found or [], MAVEN_SECRETS | {"url"}):
        if name == "url":
            url(ctx, ctx.line_at(pos), "url", text)
        elif not MAVEN_ENCRYPTED.match(text):
            secret(ctx, ctx.line_at(pos), name, text)
