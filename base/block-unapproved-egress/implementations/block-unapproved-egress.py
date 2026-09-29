#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a network command that UPLOADS data (POST/PUT/form/file) to a host outside the allowlist.
# A tool-time floor, not a network sandbox: it stops the obvious `curl -d @secrets https://unknown` reflex.
# Fetch-only traffic is left alone. Determined-adversary containment needs real sandboxing.

import os
import re
import shlex
import sys

from chock_shellparse import Cmd, commands

# The allowlist is the whole policy: hosts your stack legitimately uploads to. Defaults cover package registries and
# code hosting; add your org's own domains. A host matches if it EQUALS an entry or ends with ".<entry>".
ALLOWED_HOSTS = (
    "github.com",
    "githubusercontent.com",
    "pypi.org",
    "pythonhosted.org",
    "npmjs.org",
    "yarnpkg.com",
    "crates.io",
    "rubygems.org",
    "golang.org",
    "pkg.go.dev",
    "ghcr.io",
    "docker.io",
    "hub.docker.com",
    "quay.io",
    "dl.google.com",
    "storage.googleapis.com",
    "localhost",
    "127.0.0.1",
)
PRAGMA = "pragma: allowlist egress"
METHODS = ("POST", "PUT", "PATCH")
# curl short options that take a value (the rest of the cluster, or the next argument): -sd @f is -s and -d @f.
CURL_SHORT_VALUE = frozenset("AbcCdDeEFHKmoPQrtTuUwxXyYz")
CURL_UPLOAD_SHORT = frozenset(("-d", "-F", "-T"))
CURL_LONG_VALUE = frozenset(
    (
        *("--request", "--header", "--output", "--user-agent", "--user", "--proxy", "--cookie", "--cookie-jar"),
        *("--referer", "--max-time", "--connect-timeout", "--retry", "--resolve", "--cacert", "--cert", "--key"),
        *("--write-out", "--dump-header", "--range", "--limit-rate", "--url", "--config", "--json"),
        *("--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--form", "--form-string"),
        "--upload-file",
    )
)
WGET_LONG_VALUE = frozenset(("--post-data", "--post-file", "--body-data", "--body-file", "--method"))
POWERSHELL_FETCHERS = frozenset(("invoke-webrequest", "invoke-restmethod", "iwr", "irm"))
POWERSHELL_UPLOAD = ("method", "body", "infile", "form")
PARAM_FLOOR = 3
Options = list[tuple[str, str | None]]


def long_option(arg: str, rest: list[str], takes_value: frozenset[str]) -> tuple[str, str | None, int]:
    """A `--name[=value]` option: its name, its value, and how many following arguments it consumed."""
    name, equals, value = arg.partition("=")
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


def host_of(target: str) -> str:
    """The host of a URL, a protocol-relative `//host/path`, or a bare `host/path`, without credentials or port."""
    host = target.split("://", 1)[-1].lstrip("/").split("/", 1)[0]
    return host.rsplit("@", 1)[-1].split(":", 1)[0].lower()


def allowed(host: str) -> bool:
    return any(host == entry or host.endswith(f".{entry}") for entry in ALLOWED_HOSTS)


def bad_host(cmd: Cmd, bare: list[str]) -> str:
    """The first upload target outside the allowlist. A bare operand counts only when no explicit URL is given."""
    urls = re.findall(r"https?://[^\s\"'()<>]+", " ".join(cmd.args), re.IGNORECASE)
    hosts = [host_of(url) for url in urls] or [h for h in map(host_of, bare) if "." in h or h == "localhost"]
    return next((h for h in hosts if h and not allowed(h)), "")


def upload_target(cmd: Cmd) -> tuple[bool, str]:
    """(refuse curl -K/--config outright, upload target host to check or '') for one network command."""
    if cmd.name == "curl":
        opts, bare = curl_options(cmd.args)
        if any(name in ("-K", "--config") for name, _ in opts):
            return True, ""
        urls = [value for name, value in opts if name == "--url" and value]
        return False, bad_host(cmd, bare + urls) if curl_uploads(opts) else ""
    if cmd.name == "wget":
        return False, bad_host(cmd, [a for a in cmd.args if not a.startswith("-")]) if wget_uploads(cmd.args) else ""
    if cmd.name in POWERSHELL_FETCHERS and powershell_uploads(cmd.args):
        return False, bad_host(cmd, [a for a in cmd.args if not a.startswith("-")])
    return False, ""


def check(raw: str) -> str | None:
    """The reason a command uploads data to an unapproved host, or None."""
    if PRAGMA in raw:
        return None
    for cmd in commands(raw):
        config, host = upload_target(cmd)
        if config:
            return (
                "'curl -K/--config' reads the request URL and data from a file this guard cannot inspect, so the upload "
                "destination is not visible on the line. Inline the request, or mark a reviewed exception with "
                f"'{PRAGMA}' on the line."
            )
        if host:
            return (
                f"uploading data to '{host}' is outside the egress allowlist. Send it only to an approved host, or add "
                f"the host to ALLOWED_HOSTS, or mark a reviewed exception with '{PRAGMA}' on the line."
            )
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-unapproved-egress: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
