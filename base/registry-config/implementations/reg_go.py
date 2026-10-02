"""Go: go.mod / go.work replace directives, and how a GO* module setting's value is judged (reg_goenv finds them)."""

from __future__ import annotations

import re

from reg_core import REDIRECT, TLS, Ctx, add, digest, url

NAMES = r"(GOINSECURE|GOSUMDB|GONOSUMDB|GONOSUMCHECK|GOPRIVATE|GOPROXY|GOFLAGS)"
#: A value passed through unchanged from the environment or a CI variable: nothing to judge here.
PURE_REF = re.compile(
    r"^(?:\$[A-Za-z_]\w*|\$[0-9]|\$\{\w+\}|\$\(\w+\)|\$\{\{\s*[\w.]+\s*\}\}"
    r"|\$\{(?:localEnv|containerEnv):\w+\}|\$env:\w+)$"
)
#: Make reads `$X` as the one-letter variable X: only $(X) and ${X} pass through whole there.
MAKE_PURE = re.compile(r"^(?:\$\(\w+\)|\$\{\w+\})$")
MAKEFILE = re.compile(r"(?:^|/)(?:gnu)?makefile$|\.mk$", re.IGNORECASE)
#: A key part longer than this is keyed by its digest.
MAX_KEY = 200
#: A shell default expansion, ${NAME:-value} or ${NAME:=value}: the value applies when the name is unset.
DEFAULT = re.compile(r"^\$\{\w+:?[-=](.*)\}$")
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
    # path.Match reads a backslash-escaped character as itself, so g\ithub.com is github.com.
    item = re.sub(r"\\(.)", r"\1", pattern.strip().lower())
    host, _, rest = item.partition("/")
    if host.startswith("*.") and not GLOB & set(host[2:]) and "." in host[2:]:
        return False
    return bool(GLOB & set(host)) or (host in PUBLIC_HOSTS and not rest.strip("/*"))


def go_setting(ctx: Ctx, number: int, name: str, value: str) -> None:
    """Judge one GO* setting written with `value`."""
    value = _clean(value)
    default = DEFAULT.match(value)
    value = _clean(default[1]) if default else value
    pure = MAKE_PURE if MAKEFILE.search(ctx.path) else PURE_REF
    if not value or pure.match(value):
        return
    if "$" in value:
        # Part literal, part expansion: what Go ends up reading is not knowable from the file.
        message = f"{name} is built from an expression; what it sets is not judged here"
        add(ctx, REDIRECT, number, (name, _key(value)), message)
        return
    before = len(ctx.out)
    _literal(ctx, number, name, value)
    if "\\" in value and len(ctx.out) == before:
        # An escape the reader may resolve (\-insecure is -insecure to a shell): not judged as written.
        add(ctx, REDIRECT, number, (name, _key(value)), f"{name} holds an escape; what it sets is not judged here")


def _clean(value: str) -> str:
    """Whitespace collapsed, a trailing flow-mapping comma and the outer quotes dropped; never truncated."""
    return " ".join(value.split()).rstrip(",").strip().strip("\"'")


def _key(value: str) -> str:
    return value if len(value) <= MAX_KEY else digest(value)


def _literal(ctx: Ctx, number: int, name: str, value: str) -> None:
    """Judge a GO* value that holds no expansion."""
    # Go trims each list element, so a space after ',' or '|' hides nothing.
    items = [v.strip() for v in re.split(r"[,|]", value) if v.strip()]
    if name == "GOINSECURE" and value:
        add(
            ctx,
            TLS,
            number,
            (name, _key(value)),
            f"GOINSECURE={value[:60]} fetches those modules without TLS verification",
        )
    elif name == "GOSUMDB":
        _gosumdb(ctx, number, value)
    elif name in ("GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE") and any(_broad(i) for i in items):
        add(
            ctx, TLS, number, (name, _key(value)), f"{name}={value[:60]} skips checksum verification for public modules"
        )
    elif name == "GOFLAGS":
        _goflags(ctx, number, value)
    elif name == "GOPROXY":
        _goproxy(ctx, number, items)


def _gosumdb(ctx: Ctx, number: int, value: str) -> None:
    """GOSUMDB is `name`, `name+key` or `name+key url`: off, another database, its own key or URL all count.
    The caller has already set aside a value read from the environment or built from an expression."""
    # Read from a command line (GOSUMDB=sum.golang.org; go build), the value ends at a command separator.
    fields = re.split(r"[;&()]", value, maxsplit=1)[0].split()
    if not fields:
        return
    named = fields[0].split("+")[0].lower()
    if named == "off":
        add(ctx, TLS, number, ("GOSUMDB", "off"), "GOSUMDB=off turns checksum verification off for every module")
        return
    if named not in SUMDBS:
        # A checksum database of someone's choosing is judged like a registry host.
        url(ctx, number, "GOSUMDB", "https://" + named)
    if "+" in fields[0]:
        message = "GOSUMDB names its own verification key: a wrong key accepts any checksum"
        add(ctx, REDIRECT, number, ("GOSUMDB", _key(fields[0])), message)
    for extra in fields[1:2]:
        url(ctx, number, "GOSUMDB", extra)


def _goflags(ctx: Ctx, number: int, value: str) -> None:
    if re.search(r"(?:^|\s)--?insecure\b", value):
        add(ctx, TLS, number, ("GOFLAGS", "-insecure"), "GOFLAGS -insecure fetches modules without TLS verification")
    elif re.search(r"(?:^|\s)--?mod=mod\b", value):
        add(
            ctx,
            REDIRECT,
            number,
            ("GOFLAGS", "-mod=mod"),
            "GOFLAGS -mod=mod lets go commands rewrite go.mod and go.sum",
        )


def _goproxy(ctx: Ctx, number: int, items: list[str]) -> None:
    for element in items:
        # Read inside a command string (sh -c "GOPROXY=a,direct go build"): an element ends at whitespace or ';'.
        item = re.split(r"[\s;]", element, maxsplit=1)[0]
        if not item or item.lower() in ("direct", "off") or item.lower().startswith("file:"):
            continue  # file: is a proxy on the local disk
        # Go puts https:// before an element with '.', ':' or '/' but no ':/' (modfetch/proxy.go).
        bare = ":/" not in item and any(c in item for c in ".:/")
        url(ctx, number, "GOPROXY", "https://" + item if bare else item)
    if items and items[0].lower() == "direct":
        message = "GOPROXY=direct fetches every module from its origin, bypassing the proxy"
        add(ctx, REDIRECT, number, ("GOPROXY", "direct"), message)


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
