"""RubyGems (Gemfile), Composer, Hex (mix.exs), CocoaPods (Podfile) and SwiftPM (Package.swift)."""

from __future__ import annotations

import re

from reg_core import CONFUSION, TLS, Ctx, add, falsy, line_of, secret, truthy, url
from reg_parse import json_doc, walk

GEM_SOURCE = re.compile(r"""\bsource\b\s*\(?\s*:?\s*["']([^"']+)["']([^#\n]*)""")
QUOTED_URL = re.compile(r"""["']([A-Za-z][A-Za-z0-9+.-]*://[^"']*)["']""")
#: Composer auth keys under config, each a host map of secrets (http-basic holds username/password).
COMPOSER_AUTH = frozenset({"http-basic", "github-oauth", "gitlab-oauth", "gitlab-token", "bearer", "bitbucket-oauth"})
HEX_SETTING = re.compile(r"\b(?:repo|mirror|hex|url)\w*\s*[:=]", re.I)


def _code_lines(ctx: Ctx, comment: str) -> list[tuple[int, str]]:
    return [(n, line) for n, line in enumerate(ctx.lines, 1) if not line.lstrip().startswith(comment)]


def gemfile(ctx: Ctx) -> None:
    """Gemfile / gems.rb: source URLs (global, block or per-gem `source:`); each global source past the first asks."""
    globals_ = 0
    for number, line in _code_lines(ctx, "#"):
        for match in GEM_SOURCE.finditer(line):
            url(ctx, number, "source", match[1])
            top = line.lstrip().startswith("source") and not re.search(r"\bdo\b|\{", match[2])
            globals_ += top
            if top and globals_ > 1:
                add(
                    ctx,
                    CONFUSION,
                    number,
                    ("source", "global"),
                    "a second global source: Bundler may resolve a gem from either",
                )


def composer(ctx: Ctx) -> None:
    """composer.json: repository URLs, secure-http, disable-tls, auth written out, allow-plugins wildcards."""
    doc = json_doc(ctx)
    if not isinstance(doc, dict):
        return
    for path, value in walk(doc.get("repositories", [])):
        if path and path[-1] == "url":
            kind = str(doc["repositories"][_index(path[0])].get("type", "composer")).lower()
            url(ctx, line_of(ctx, str(value)), "repositories.url", value, registry=kind == "composer")
    config = doc.get("config")
    if not isinstance(config, dict):
        return
    for path, value in walk(config):
        top, leaf = path[0], path[-1]
        number = line_of(ctx, f'"{leaf}"')
        if top == "secure-http" and falsy(value):
            add(ctx, TLS, number, (top, "false"), "secure-http false lets Composer fetch over http")
        elif top == "disable-tls" and truthy(value):
            add(ctx, TLS, number, (top, "true"), "disable-tls true turns TLS off for Composer")
        elif top in COMPOSER_AUTH and leaf != "username":
            secret(ctx, number, ".".join(path), value)
        elif top == "allow-plugins" and (
            (path == ("allow-plugins",) and value is True) or (leaf == "*" and value is True)
        ):
            add(ctx, CONFUSION, number, (top, "*"), "allow-plugins lets every installed package run a Composer plugin")


def _index(key: str) -> int | str:
    """A repositories entry's position: a list index, or the key of a map of repositories."""
    return int(key) if key.isdigit() else key


def mix(ctx: Ctx) -> None:
    """mix.exs: Hex unsafe_https, and clear-text URLs on repo, mirror or hex settings."""
    for number, line in _code_lines(ctx, "#"):
        if re.search(r"\bunsafe_https:\s*true\b|HEX_UNSAFE_HTTPS", line):
            add(ctx, TLS, number, ("unsafe_https", "true"), "unsafe_https turns TLS verification off for Hex")
        if HEX_SETTING.search(line):
            for match in QUOTED_URL.finditer(line):
                url(ctx, number, "hex", match[1], registry=False)


def podfile(ctx: Ctx) -> None:
    """Podfile: spec repo sources served in clear text (private spec repos on git hosts are normal)."""
    for number, line in _code_lines(ctx, "#"):
        for match in GEM_SOURCE.finditer(line):
            url(ctx, number, "source", match[1], registry=False)


def swift(ctx: Ctx) -> None:
    """Package.swift: a package URL in clear text."""
    for number, line in _code_lines(ctx, "//"):
        if ".package(" in line or "url:" in line:
            for match in QUOTED_URL.finditer(line):
                url(ctx, number, "package", match[1], registry=False)
