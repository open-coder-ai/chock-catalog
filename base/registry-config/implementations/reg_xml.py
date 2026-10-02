"""NuGet (nuget.config, Directory.Build.props) and Maven settings.xml, read with patterns, never an XML parser."""

from __future__ import annotations

import html
import re

from reg_core import CONFUSION, TLS, Ctx, add, norm, secret, truthy, url
from reg_parse import refuse

COMMENT = re.compile(r"<!--.*?-->", re.S)
ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
#: A start tag's attributes: a '>' inside a quoted value does not end the tag.
TAG_BODY = r"""((?:[^>"']|"[^"]*"|'[^']*')*)"""
ADD = re.compile(rf"<add\b{TAG_BODY}>", re.I)
#: Credential keys NuGet reads from packageSourceCredentials and from <config>.
NUGET_SECRETS = frozenset({"cleartextpassword", "password", "http_proxy.password"})
RESTORE = re.compile(rf"<(RestoreSources|RestoreAdditionalProjectSources)\b{TAG_BODY}>(.*?)</\1\s*>", re.I | re.S)
MAVEN_URL = re.compile(rf"<url\b{TAG_BODY}>\s*(.*?)\s*</url\s*>", re.I | re.S)
MAVEN_SECRET = re.compile(rf"<(password|passphrase)\b{TAG_BODY}>\s*(.*?)\s*</\1\s*>", re.I | re.S)


class XmlError(ValueError):
    pass


def _clean(ctx: Ctx) -> str | None:
    """The text with comments blanked (line breaks kept), or None (and a finding) for an unclosed comment.
    CDATA and DOCTYPE are refused: entity and CDATA tricks could hide a value from the patterns."""
    text = COMMENT.sub(lambda m: "\n" * m[0].count("\n"), ctx.text)
    for mark, what in (("<!--", "an unclosed comment"), ("<![CDATA[", "a CDATA section"), ("<!DOCTYPE", "a DOCTYPE")):
        if mark.lower() in text.lower():
            refuse(ctx, "XML file", XmlError(f"{what} is not read here"))
            return None
    return text


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _attrs(body: str) -> dict[str, str]:
    return {m[1].lower(): html.unescape(m[2] if m[2] is not None else m[3]) for m in ATTR.finditer(body)}


def _section(text: str, name: str) -> tuple[int, str] | None:
    match = re.search(rf"<{name}\b{TAG_BODY}(?:(?<=/)>|>(.*?)</{name}\s*>)", text, re.I | re.S)
    if match is None:
        return None
    return (match.start(2), match[2]) if match[2] is not None else (match.start(), "")


def nuget(ctx: Ctx) -> None:
    text = _clean(ctx)
    if text is None:
        return
    sources = _section(text, "packageSources")
    if sources is not None:
        start, body = sources
        adds = [(start + m.start(), _attrs(m[1])) for m in ADD.finditer(body)]
        for pos, attrs in adds:
            number = _line(text, pos)
            url(ctx, number, f"packageSources.{attrs.get('key', '')}", attrs.get("value", ""))
            if truthy(attrs.get("allowinsecureconnections", "")):
                add(
                    ctx,
                    TLS,
                    number,
                    ("allowInsecureConnections", attrs.get("key", "")),
                    "allowInsecureConnections lets a source serve over http",
                )
        cleared = re.search(r"<clear\b", body, re.I) is not None
        mapped = re.search(r"<packageSourceMapping\b", text, re.I) is not None
        if adds and (not cleared or (len(adds) > 1 and not mapped)):
            why = (
                "no <clear/>: sources from user and machine configs also resolve"
                if not cleared
                else "no packageSourceMapping"
            )
            add(
                ctx,
                CONFUSION,
                _line(text, start),
                ("packageSources", f"{cleared}|{mapped}"),
                f"{why}, so a name may come from any source",
            )
    for match in ADD.finditer(text):
        attrs = _attrs(match[1])
        key = attrs.get("key", "").lower()
        number = _line(text, match.start())
        if key in NUGET_SECRETS:
            secret(ctx, number, key, attrs.get("value", ""))
        elif key == "signaturevalidationmode" and norm(attrs.get("value", "")).lower() == "accept":
            add(ctx, TLS, number, (key, "accept"), "signatureValidationMode accept installs unsigned packages")


def props(ctx: Ctx) -> None:
    """Directory.Build.props: RestoreSources and RestoreAdditionalProjectSources, ';'-separated."""
    text = _clean(ctx)
    for match in RESTORE.finditer(text or ""):
        for item in html.unescape(match[3]).split(";"):
            url(ctx, _line(text, match.start()), match[1], item.strip())


def maven(ctx: Ctx) -> None:
    """Maven settings.xml: mirror and repository URLs, written-out server passwords."""
    text = _clean(ctx)
    if text is None or "<settings" not in text:
        return
    for match in MAVEN_URL.finditer(text):
        url(ctx, _line(text, match.start()), "url", html.unescape(match[2]))
    for match in MAVEN_SECRET.finditer(text):
        secret(ctx, _line(text, match.start()), match[1].lower(), html.unescape(match[3]))
