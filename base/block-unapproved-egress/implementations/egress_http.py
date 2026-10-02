"""curl, wget and Invoke-WebRequest: what they upload, where they send it, and the options that reroute a request."""

from __future__ import annotations

import re

from chock_shellparse import Cmd, after
from egress_core import (
    ASK_PERSON,
    COMMAND_SUBST,
    VARIABLE,
    WHOLE_VARIABLE,
    Allowlist,
    Verdict,
    confirm,
    permitted,
    refuse,
    unapproved,
)

METHODS = ("POST", "PUT", "PATCH")
# curl short options that take a value (the rest of the cluster, or the next argument): -sd @f is -s and -d @f.
CURL_SHORT_VALUE = frozenset("AbcCdDeEFHKmoPQrtTuUwxXyYz")
CURL_UPLOAD_SHORT = frozenset(("-d", "-F", "-T"))
CURL_LONG_VALUE = frozenset(
    (
        *("--request", "--header", "--output", "--user-agent", "--user", "--proxy", "--cookie", "--cookie-jar"),
        *("--referer", "--max-time", "--connect-timeout", "--retry", "--resolve", "--cacert", "--cert", "--key"),
        *("--write-out", "--dump-header", "--range", "--limit-rate", "--url", "--config", "--json", "--connect-to"),
        *("--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--form", "--form-string"),
        "--upload-file",
    )
)
WGET_LONG_VALUE = frozenset(("--post-data", "--post-file", "--body-data", "--body-file", "--method"))
POWERSHELL_FETCHERS = frozenset(("invoke-webrequest", "invoke-restmethod", "iwr", "irm"))
POWERSHELL_UPLOAD = ("method", "body", "infile", "form")
PARAM_FLOOR = 2
URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'()<>]+")
BARE_HOST = re.compile(r"(?:0x[0-9a-f]+|[0-9]+|\[.*)(?:[/:].*)?", re.IGNORECASE)
REROUTE = {"-x": "--proxy", "--proxy": "--proxy", "--resolve": "--resolve", "--connect-to": "--connect-to"}
PREFIX_FLOOR = 4
UPLOAD_LONG = frozenset(("--upload-file", "--json", "--post-data", "--post-file", "--body-data", "--body-file"))
PROXY_ENV = frozenset(("http_proxy", "https_proxy", "all_proxy"))
HEADER_OPTS = frozenset(("-H", "--header", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-u", "--user"))
Options = list[tuple[str, str | None]]


def canonical(name: str, known: frozenset[str]) -> str:
    """An unambiguous-looking prefix (`--upl`, `--js`) as the option it abbreviates; upload options win a tie (fail closed)."""
    if name in known or len(name) < PREFIX_FLOOR:
        return name
    hits = sorted(opt for opt in known if opt.startswith(name))
    return next((h for h in hits if h in UPLOAD_LONG or h.startswith(("--data", "--form"))), hits[0] if hits else name)


def long_option(arg: str, rest: list[str], takes_value: frozenset[str]) -> tuple[str, str | None, int]:
    """A `--name[=value]` option: its name, its value, and how many following arguments it consumed."""
    name, equals, value = arg.partition("=")
    name = canonical(name, takes_value)
    if equals:
        return name, value, 0
    if name in takes_value and rest:
        return name, rest[0], 1
    return name, None, 0


def curl_options(args: list[str]) -> tuple[Options, list[str]]:
    """curl's options as (name, value) pairs -- clusters split, attached values kept -- and its bare operands."""
    opts: Options = []
    bare: list[str] = []
    i = 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg.startswith("--"):
            name, value, used = long_option(arg, args[i:], CURL_LONG_VALUE)
            opts.append((name, value))
            i += used
        elif arg.startswith("-") and len(arg) > 1:
            for pos, char in enumerate(arg[1:], 1):
                if char in CURL_SHORT_VALUE:
                    value = arg[pos + 1 :] or (args[i] if i < len(args) else "")
                    i += 0 if arg[pos + 1 :] else 1
                    opts.append((f"-{char}", value))
                    break
                opts.append((f"-{char}", None))
        else:
            bare.append(arg)
    return opts, bare


def curl_uploads(opts: Options) -> bool:
    """-d/-F/-T (any --data*, --form*, --upload-file, --json) or a POST/PUT/PATCH method."""
    for name, value in opts:
        upload = name in ("--upload-file", "--json") or name.startswith(("--data", "--form"))
        if upload or name in CURL_UPLOAD_SHORT:
            return True
        if name in ("-X", "--request") and (value or "").upper() in METHODS:
            return True
    return False


def wget_uploads(args: list[str]) -> bool:
    """--post-data/--post-file/--body-data/--body-file or --method POST|PUT|PATCH."""
    i = 0
    while i < len(args):
        arg, i = args[i], i + 1
        if not arg.startswith("--"):
            continue
        name, value, used = long_option(arg, args[i:], WGET_LONG_VALUE)
        i += used
        if name == "--method" and (value or "").upper() in METHODS:
            return True
        if name in WGET_LONG_VALUE and name != "--method":
            return True
    return False


def powershell_uploads(args: list[str]) -> bool:
    """-Method POST|PUT|PATCH, -Body, -InFile, -Form: parameters bind with a space or a colon, in any case."""
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            continue
        name, _, value = arg[1:].lower().partition(":")
        param = next((p for p in POWERSHELL_UPLOAD if len(name) >= PARAM_FLOOR and p.startswith(name)), "")
        follows = value or (args[i + 1].lower() if i + 1 < len(args) else "")
        if param == "method" and follows.upper() in METHODS:
            return True
        if param and param != "method":
            return True
    return False


def targets(args: list[str], bare: list[str]) -> list[str]:
    """Every URL in the arguments; with none, the bare operands that read as a host (dotted name, localhost, number, variable)."""
    urls = [u for u in URL.findall(" ".join(args)) if not u.lower().startswith("file:")]
    return urls or [
        b
        for b in bare
        if any(dot in b for dot in ".\u3002\uff0e\uff61")
        or b == "localhost"
        or BARE_HOST.fullmatch(b)
        or COMMAND_SUBST.search(b)
        or WHOLE_VARIABLE.fullmatch(b)
    ]


def reroutes(opts: Options) -> Verdict:
    """--proxy/-x, --resolve, --connect-to and a Host: header send the request somewhere its URL does not say."""
    for name, value in opts:
        if name in REROUTE or (name in ("-H", "--header") and (value or "").lstrip().lower().startswith("host:")):
            what = REROUTE.get(name, "a Host: header")
            return confirm(f"curl {what} sends the request to a destination its URL does not show. {ASK_PERSON}")
    return None


def proxied(cmd: Cmd) -> Verdict:
    """A *_PROXY variable in front of curl or wget, or wget -e http_proxy=..., reroutes it like --proxy does."""
    settings = [a[2:] for a in cmd.args if a.startswith("-e") and a[2:]]
    settings += [after(cmd.args, "-e"), after(cmd.args, "--execute")]
    wget_setting = cmd.name == "wget" and any("proxy" in v.lower() for v in settings)
    if PROXY_ENV & {name.lower() for name in cmd.env} or wget_setting:
        return confirm(
            f"a proxy setting for {cmd.name} sends the request through a host the URL does not show. {ASK_PERSON}"
        )
    return None


def wget_options(args: list[str]) -> Options:
    """wget's header-like options as (curl-style name, value) pairs."""
    names = {
        "--header": "-H",
        "--user-agent": "-A",
        "--referer": "-e",
        "--user": "-u",
        "--password": "-u",
        "--load-cookies": "-b",
    }
    opts: Options = []
    for index, arg in enumerate(args):
        name, equals, value = arg.partition("=")
        if name in names:
            opts.append((names[name], value if equals else (args[index + 1] if index + 1 < len(args) else "")))
    return opts


def header_exfil(allow: Allowlist, opts: Options, urls: list[str]) -> Verdict:
    """A substitution, variable or @file in a header, cookie, referer or user value sent to a host outside the allowlist."""
    carries = any(
        COMMAND_SUBST.search(v or "") or VARIABLE.search(v or "") or (v or "").startswith("@")
        for n, v in opts
        if n in HEADER_OPTS
    )
    if carries and any(not permitted(allow, url) for url in urls):
        return confirm(
            f"a command, variable or file value goes in a header to a host outside the egress allowlist. {ASK_PERSON}"
        )
    return None


def http_target(cmd: Cmd, allow: Allowlist) -> tuple[list[str], bool, Verdict]:
    """(URL targets, whether the command uploads, a verdict that needs no host) for curl, wget and iwr/irm."""
    if cmd.name == "curl":
        opts, bare = curl_options(cmd.args)
        if any(name in ("-K", "--config") for name, _ in opts):
            return (
                [],
                False,
                refuse(
                    "'curl -K/--config' reads the request URL and data from a file this guard cannot inspect, so the upload "
                    "destination is not visible on the line. Inline the request, or ask the person to run it."
                ),
            )
        urls = [value for name, value in opts if name == "--url" and value]
        found = targets(cmd.args, bare + urls)
        return found, curl_uploads(opts), reroutes(opts) or proxied(cmd) or header_exfil(allow, opts, found)
    if cmd.name == "wget":
        found = targets(cmd.args, [a for a in cmd.args if not a.startswith("-")])
        return found, wget_uploads(cmd.args), proxied(cmd) or header_exfil(allow, wget_options(cmd.args), found)
    if cmd.name in POWERSHELL_FETCHERS:
        return targets(cmd.args, [a for a in cmd.args if not a.startswith("-")]), powershell_uploads(cmd.args), None
    return [], False, None


def upload_verdict(allow: Allowlist, urls: list[str]) -> Verdict:
    """The first upload target outside the allowlist."""
    return next((v for url in urls if (v := unapproved(allow, "uploading data to", url))), None)
