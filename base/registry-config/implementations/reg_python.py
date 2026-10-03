"""pip, uv, Poetry, PDM, pipenv, twine and conda index settings."""

from __future__ import annotations

import configparser
import re
import shlex

from reg_core import CONFUSION, TLS, UNREADABLE, Ctx, add, digest, falsy, line_of, norm, secret, url
from reg_parse import refuse, toml, walk, yaml_scalars

#: The pip options a requirements file may carry that choose an index, and the shortest prefix of each that
#: pip's option parser (optparse) still reads as that option and no other requirements-file option.
#: shlex builds a long word in quadratic time; no real requirement line comes near this.
MAX_LINE = 1 << 16
LONG_OPTIONS = {"index-url": 1, "extra-index-url": 2, "find-links": 1, "trusted-host": 1}
COMMENT = re.compile(r"(?:^|\s)#.*$")
URL_KEYS = frozenset({"index-url", "extra-index-url", "find-links", "url", "publish-url", "check-url", "repository"})
INSECURE_KEYS = frozenset({"trusted-host", "allow-insecure-host"})


def _option(ctx: Ctx, number: int, option: str, value: str) -> None:
    """One pip index option, however it was written (requirements line, config key, TOML key)."""
    name = {"-i": "index-url", "-f": "find-links"}.get(option, option.lstrip("-").replace("_", "-"))
    if name in INSECURE_KEYS:
        add(ctx, TLS, number, (name, norm(value).lower()), f"{name} {norm(value)[:80]} turns TLS verification off")
        return
    # find-links and the upload URLs name where files are read from or sent, not the index a name resolves in.
    url(ctx, number, name, value, registry=name not in ("find-links", "publish-url", "check-url"))
    if name == "extra-index-url":
        add(
            ctx,
            CONFUSION,
            number,
            (name, norm(value).split("@")[-1]),
            "--extra-index-url: pip takes the highest version from any index, so a public package can shadow a private name",
        )


def requirements(ctx: Ctx) -> None:
    """requirements*.txt / *.in option lines; a trailing backslash joins the next line, '#' after space comments."""
    logical: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, raw in enumerate(ctx.lines, 1):
        start = start or number
        body = COMMENT.sub("", raw)
        if body.endswith("\\"):
            pending += body[:-1] + " "
            continue
        logical.append((start, pending + body))
        pending, start = "", 0
    if pending:
        logical.append((start, pending))
    for number, line in logical:
        _options(ctx, number, line)


def _options(ctx: Ctx, number: int, line: str) -> None:
    """Judge the index options in one logical line; one too long to split in time is refused."""
    if len(line.strip()) > MAX_LINE:
        add(
            ctx,
            UNREADABLE,
            number,
            ("long line", digest(line)),
            f"a line longer than {MAX_LINE} characters is not read",
        )
        return
    for option, value in pip_options(line):
        _option(ctx, number, option, value)


def pip_options(line: str) -> list[tuple[str, str]]:
    """The index options in one requirements line, read as pip reads them: words split the shell way (quotes
    join and drop), a long option by any prefix optparse accepts, its value after '=' or as the next word."""
    try:
        words = shlex.split(line)
    except ValueError:
        words = line.split()
    out: list[tuple[str, str]] = []
    rest = iter(words)
    for word in rest:
        if word.startswith("--"):
            name, eq, value = word[2:].partition("=")
            full = next((f for f, least in LONG_OPTIONS.items() if f.startswith(name) and len(name) >= least), None)
            if full:
                out.append(("--" + full, value if eq else next(rest, "")))
        elif word[:2] in ("-i", "-f"):
            out.append((word[:2], word[2:] or next(rest, "")))
    return out


def _config(ctx: Ctx) -> configparser.ConfigParser | None:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(ctx.text)
    except configparser.Error as exc:
        refuse(ctx, "INI file", exc)
        return None
    return parser


def pip_conf(ctx: Ctx) -> None:
    """pip.conf / pip.ini: index-url, extra-index-url, find-links, trusted-host (multi-line values split)."""
    parser = _config(ctx)
    if parser is None:
        return
    for section in parser.sections():
        for key, value in parser.items(section):
            name = key.replace("_", "-")
            if name in URL_KEYS - {"url", "repository"} or name in INSECURE_KEYS:
                for item in value.split():
                    _option(ctx, line_of(ctx, item), "--" + name, item)


def pypirc(ctx: Ctx) -> None:
    """.pypirc: upload passwords written out, and clear-text repository URLs."""
    parser = _config(ctx)
    if parser is None:
        return
    for section in parser.sections():
        for key, value in parser.items(section):
            number = line_of(ctx, key)
            if key == "password":
                secret(ctx, number, f"{section}.password", value)
            elif key == "repository":
                url(ctx, number, f"{section}.repository", value, registry=False)


def _toml_index(ctx: Ctx, tree: object, root: tuple[str, ...]) -> None:
    """Every index setting under a uv, Poetry or PDM table, by the name of its leaf key."""
    for path, value in walk(tree, root):
        key = next((p for p in reversed(path) if not p.isdigit()), "")
        name, number = key.replace("_", "-"), line_of(ctx, key)
        if "sources" in path[:2] and name in ("url", "git"):
            # [tool.uv.sources]: a direct URL or git source for one package, not an index; clear text only.
            url(ctx, number, ".".join(path), str(value), registry=False)
        elif name in URL_KEYS - {"repository"} or name in INSECURE_KEYS:
            _option(ctx, number, "--" + name, str(value))
        elif name == "index-strategy" and str(value).startswith("unsafe"):
            add(ctx, CONFUSION, number, (name, norm(value)), f"index-strategy {value} lets any index supply any name")
        elif name == "verify-ssl" and falsy(value):
            add(ctx, TLS, number, (name, "false"), "verify_ssl = false turns TLS verification off")
        elif name in ("password", "token"):
            secret(ctx, number, ".".join(path), value)


def uv_toml(ctx: Ctx) -> None:
    doc = toml(ctx)
    if doc is not None:
        _toml_index(ctx, doc, ("uv",))


def pyproject(ctx: Ctx) -> None:
    """pyproject.toml: [tool.uv], [[tool.poetry.source]] and [[tool.pdm.source]] only."""
    doc = toml(ctx)
    tool = doc.get("tool") if isinstance(doc, dict) else None
    if not isinstance(tool, dict):
        return
    for name in ("uv", "pdm"):
        if name in tool:
            _toml_index(ctx, tool[name], (name,))
    poetry = tool.get("poetry")
    if isinstance(poetry, dict) and "source" in poetry:
        _toml_index(ctx, poetry["source"], ("poetry", "source"))


def pipfile(ctx: Ctx) -> None:
    """Pipfile [[source]]: url, verify_ssl; more than one source with no per-package index asks."""
    doc = toml(ctx)
    sources = doc.get("source") if isinstance(doc, dict) else None
    if not isinstance(sources, list):
        return
    _toml_index(ctx, sources, ("source",))
    if len(sources) > 1:
        add(
            ctx,
            CONFUSION,
            line_of(ctx, "[[source]]"),
            ("source", str(len(sources))),
            "more than one [[source]]: a name may resolve from either",
        )


def condarc(ctx: Ctx) -> None:
    """.condarc and environment.yml: channel URLs, channel_alias, custom channels, ssl_verify, pip options."""
    nodes = yaml_scalars(ctx)
    for path, value, number in nodes or ():
        top = path[0] if path else ""
        if top in ("channels", "default_channels", "channel_alias", "custom_channels", "custom_multichannels"):
            url(ctx, number, top, value)
        elif top == "ssl_verify" and falsy(value):
            add(ctx, TLS, number, (top, "false"), "ssl_verify: false turns TLS verification off")
        elif top == "dependencies":
            _options(ctx, number, value)
