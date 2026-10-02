"""Go: go.mod / go.work replace directives, and GO* module settings in Dockerfiles, Makefiles, env and CI files."""

from __future__ import annotations

import re

from reg_core import REDIRECT, TLS, Ctx, add, norm, url

#: A GO* setting as Dockerfile ENV/ARG, shell or make assignment, YAML or `go env -w` writes one; never a ${GO...} read.
GO_SETTING = re.compile(
    r"(?<![\w$])(?<!\$\{)(GOINSECURE|GOSUMDB|GONOSUMDB|GONOSUMCHECK|GOPRIVATE|GOPROXY|GOFLAGS)"
    r"[\"']?(?:\s*[:?+]?=\s*|\s*:\s+|\s+(?=[\"'\w*.,/-]))[\"']?([^\"'\s#;]*(?:\s+-[\w=.,-]+)*)"
)
#: Hosts anyone can publish modules under: a pattern naming one of them with no path is every module there.
PUBLIC_HOSTS = frozenset(
    {"github.com", "gitlab.com", "bitbucket.org", "golang.org", "gopkg.in", "go.googlesource.com", "google.golang.org"}
)
#: (old path, new path or folder, new version): the version is part of what a replace points at.
REPLACE_ONE = re.compile(r"^\s*replace\s+(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?")
BLOCK_START = re.compile(r"^\s*replace\s*\(\s*$")
REPLACE_ENTRY = re.compile(r"^\s*(\S+)(?:\s+v\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?")
GLOB = frozenset("*?[")
#: The public checksum databases; any other GOSUMDB name is a database of someone's choosing.
SUMDBS = frozenset({"sum.golang.org", "sum.golang.google.cn"})


def _broad(pattern: str) -> bool:
    """A GOPRIVATE/GONOSUMDB element that covers modules anyone can publish. Go matches each element, as a
    path.Match glob, against a prefix of the module path, so the host part decides: any glob there other than
    a leading '*.' over a domain of two or more labels is broad, as is a public code host with no owner
    after it (github.com, github.com/*)."""
    item = pattern.strip().lower()
    host, _, rest = item.partition("/")
    if host.startswith("*.") and not GLOB & set(host[2:]) and "." in host[2:]:
        return False
    return bool(GLOB & set(host)) or (host in PUBLIC_HOSTS and not rest.strip("/*"))


def go_setting(ctx: Ctx, number: int, name: str, value: str) -> None:
    """Judge one GO* setting written with `value`."""
    value = norm(value)
    items = [v for v in re.split(r"[,|]", value) if v]
    if name == "GOINSECURE" and value:
        add(ctx, TLS, number, (name, value), f"GOINSECURE={value[:60]} fetches those modules without TLS verification")
    elif name == "GOSUMDB" and value.lower() == "off":
        add(ctx, TLS, number, (name, "off"), "GOSUMDB=off turns checksum verification off for every module")
    elif name == "GOSUMDB" and value and value.split("+")[0].lower() not in SUMDBS:
        # A checksum database of someone's choosing is judged like a registry host.
        url(ctx, number, name, "https://" + value.split("+")[0])
    elif name in ("GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE") and any(_broad(i) for i in items):
        add(ctx, TLS, number, (name, value), f"{name}={value[:60]} skips checksum verification for public modules")
    elif name == "GOFLAGS":
        _goflags(ctx, number, value)
    elif name == "GOPROXY":
        _goproxy(ctx, number, items)


def _goflags(ctx: Ctx, number: int, value: str) -> None:
    if re.search(r"(?:^|\s)-insecure\b", value):
        add(ctx, TLS, number, ("GOFLAGS", "-insecure"), "GOFLAGS -insecure fetches modules without TLS verification")
    elif re.search(r"(?:^|\s)-mod=mod\b", value):
        add(
            ctx,
            REDIRECT,
            number,
            ("GOFLAGS", "-mod=mod"),
            "GOFLAGS -mod=mod lets go commands rewrite go.mod and go.sum",
        )


def _goproxy(ctx: Ctx, number: int, items: list[str]) -> None:
    for item in items:
        if item.lower().startswith(("http://", "https://")):
            url(ctx, number, "GOPROXY", item)
    if items and items[0].lower() == "direct":
        message = "GOPROXY=direct fetches every module from its origin, bypassing the proxy"
        add(ctx, REDIRECT, number, ("GOPROXY", "direct"), message)


def go_env(ctx: Ctx) -> None:
    """GO* settings on any non-comment line of a Dockerfile, Makefile, env or CI file."""
    for number, raw in enumerate(ctx.lines, 1):
        if raw.lstrip().startswith(("#", "//")):
            continue
        for match in GO_SETTING.finditer(raw):
            go_setting(ctx, number, match[1], match[2])


def _replace(ctx: Ctx, number: int, old: str, new: str) -> None:
    local = new.startswith(("./", "../", "/")) or new in (".", "..")
    detail = "local" if local else "module"
    where = "a local folder" if local else f"another module ({new[:80]})"
    add(ctx, REDIRECT, number, (f"replace {old}", f"{detail} {new}"), f"replace {old[:80]} => {where}")


def gomod(ctx: Ctx) -> None:
    """go.mod / go.work: every replace (single or block) asks; a version-only replace of the same path is a pin."""
    inside = False
    for number, raw in enumerate(ctx.lines, 1):
        line = raw.split("//", 1)[0]
        if inside:
            if line.strip() == ")":
                inside = False
                continue
            match = REPLACE_ENTRY.match(line)
        elif BLOCK_START.match(line):
            inside = True
            continue
        else:
            match = REPLACE_ONE.match(line)
        if match and match[2] != match[1]:
            _replace(ctx, number, match[1], " ".join(filter(None, (match[2], match[3]))))
