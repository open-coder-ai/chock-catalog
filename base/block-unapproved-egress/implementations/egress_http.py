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


def words(table: str) -> tuple[str, ...]:
    """A table of option names written one per word."""
    return tuple(table.split())


# Short options that take a value (the rest of the cluster, or the next argument): -sd @f is -s and -d @f.
CURL_SHORT = {char: f"-{char}" for char in "AbcCdDeEFHKmoPQrtTuUwxXyYz"}
CURL_UPLOAD_SHORT = frozenset(("-d", "-F", "-T"))
# Long options that take a value. The target is an operand, so a URL in a value (-e, -H, -A, -d, --json) excuses nothing.
CURL_LONG_VALUE = frozenset(
    words("""
    --request --header --output --user-agent --user --proxy --cookie --cookie-jar --referer --max-time
    --connect-timeout --retry --resolve --cacert --cert --key --write-out --dump-header --range --limit-rate --url
    --config --json --connect-to --data --data-binary --data-raw --data-urlencode --data-ascii --form --form-string
    --upload-file --upload-flags --url-query --request-target --variable --rate --parallel-max --capath --cert-type
    --key-type --ciphers --tls-max --pass --pubkey --pinnedpubkey --interface --local-port --unix-socket
    --abstract-unix-socket --dns-servers --doh-url --noproxy --proxy-user --proxy-header --proxy-cacert --proxy-cert
    --proxy-key --socks4 --socks4a --socks5 --socks5-hostname --max-filesize --max-redirs --retry-delay
    --retry-max-time --speed-limit --speed-time --keepalive-time --continue-at --time-cond --stderr --trace
    --trace-ascii --output-dir --oauth2-bearer --netrc-file --proto --proto-redir --proto-default --etag-save
    --etag-compare --aws-sigv4 --tlsuser --tlspassword
    --hsts --alt-svc
    """)
)
WGET_SHORT = dict(
    zip(
        "eoaiBtOTwQPUARDIXl",
        words("""
        --execute --output-file --append-output --input-file --base --tries --output-document --timeout --wait --quota
        --directory-prefix --user-agent --accept --reject --domains --include-directories --exclude-directories --level
        """),
    )
)
WGET_UPLOAD = frozenset(("--post-data", "--post-file", "--body-data", "--body-file"))
WGET_LONG_VALUE = frozenset(
    (
        *WGET_UPLOAD,
        *WGET_SHORT.values(),
        *words("""
        --method --header --referer --user --password --http-user --http-password --proxy-user --proxy-password
        --ftp-user --ftp-password --load-cookies --save-cookies --dns-timeout --connect-timeout --read-timeout
        --waitretry --bind-address --limit-rate --cut-dirs --accept-regex --reject-regex --regex-type
        --exclude-domains --max-redirect --ca-certificate --ca-directory --certificate --certificate-type
        --private-key --private-key-type --secure-protocol --pinnedpubkey --hsts-file --progress --rejected-log
        --warc-file --warc-header --warc-max-size --warc-tempdir --local-encoding --remote-encoding --prefer-family
        --restrict-file-names --default-page --start-pos --compression --use-askpass --config --egd-file
        --random-file
        """),
    )
)
# wget's header-like options under curl's names, so one header check reads both.
WGET_AS_CURL = {
    "--header": "-H",
    "--user-agent": "-A",
    "--referer": "-e",
    "--user": "-u",
    "--password": "-u",
    "--load-cookies": "-b",
}
POWERSHELL_FETCHERS = frozenset(("invoke-webrequest", "invoke-restmethod", "iwr", "irm"))
# Parameters that take a value, upload ones first so an ambiguous prefix (-Bo, -In) reads as the upload. The rest are switches.
POWERSHELL_VALUE = words(
    """
    method body infile form uri headers useragent outfile contenttype proxy proxycredential credential certificate
    certificatethumbprint websession sessionvariable timeoutsec maximumredirection maximumretrycount retryintervalsec
    transferencoding sslprotocol token authentication custommethod responseheadersvariable statuscodevariable
    httpversion unixsocket connectiontimeoutseconds operationtimeoutseconds erroraction warningaction
    informationaction errorvariable warningvariable informationvariable outvariable outbuffer pipelinevariable
    progressaction
    """
)
POWERSHELL_UPLOAD = frozenset(("body", "infile", "form"))
PARAM_FLOOR = 2
URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'()<>]+")
BARE_HOST = re.compile(r"(?:0x[0-9a-f]+|[0-9]+|\[.*)(?:[/:].*)?", re.IGNORECASE)
REROUTE = {"-x": "--proxy", "--proxy": "--proxy", "--resolve": "--resolve", "--connect-to": "--connect-to"}
PREFIX_FLOOR = 4
UPLOAD_LONG = frozenset(("--upload-file", "--json", *WGET_UPLOAD))
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


def options(args: list[str], short: dict[str, str], long: frozenset[str]) -> tuple[Options, list[str]]:
    """A getopt-style command's options as (name, value) pairs -- clusters split, attached values kept -- and its operands."""
    opts: Options = []
    bare: list[str] = []
    i = 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg.startswith("--"):
            name, value, used = long_option(arg, args[i:], long)
            opts.append((name, value))
            i += used
        elif arg.startswith("-") and len(arg) > 1:
            for pos, char in enumerate(arg[1:], 1):
                if char in short:
                    value = arg[pos + 1 :] or (args[i] if i < len(args) else "")
                    i += 0 if arg[pos + 1 :] else 1
                    opts.append((short[char], value))
                    break
                opts.append((f"-{char}", None))
        else:
            bare.append(arg)
    return opts, bare


def curl_options(args: list[str]) -> tuple[Options, list[str]]:
    """curl's options and its bare operands (the URLs)."""
    return options(args, CURL_SHORT, CURL_LONG_VALUE)


def wget_options(args: list[str]) -> tuple[Options, list[str]]:
    """wget's options (short forms by their long names, header-like ones by curl's) and its bare operands (the URLs)."""
    opts, bare = options(args, WGET_SHORT, WGET_LONG_VALUE)
    return [(WGET_AS_CURL.get(name, name), value) for name, value in opts], bare


def powershell_options(args: list[str]) -> tuple[Options, list[str]]:
    """Invoke-WebRequest parameters as (name, value): `-Name value` or `-Name:value` in any case, by prefix; switches take nothing."""
    opts: Options = []
    bare: list[str] = []
    i = 0
    while i < len(args):
        arg, i = args[i], i + 1
        if not arg.startswith("-") or len(arg) < PARAM_FLOOR:
            bare.append(arg)
            continue
        name, bound, value = arg[1:].lower().partition(":")
        param = next((p for p in POWERSHELL_VALUE if len(name) >= PARAM_FLOOR and p.startswith(name)), "")
        if param and not bound:
            value, i = (args[i], i + 1) if i < len(args) else ("", i)
        opts.append((param or name, value if param else None))
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


def wget_uploads(opts: Options) -> bool:
    """--post-data/--post-file/--body-data/--body-file or --method POST|PUT|PATCH."""
    return any(name in WGET_UPLOAD or (name == "--method" and (value or "").upper() in METHODS) for name, value in opts)


def powershell_uploads(opts: Options) -> bool:
    """-Method POST|PUT|PATCH, -Body, -InFile, -Form."""
    return any(
        name in POWERSHELL_UPLOAD or (name == "method" and (value or "").upper() in METHODS) for name, value in opts
    )


def targets(operands: list[str]) -> list[str]:
    """Each operand that is a URL (`file:` aside) or reads as a host: a dotted name, localhost, a number, a variable, a substitution."""
    found: list[str] = []
    for operand in operands:
        url = URL.search(operand)
        if url:
            found += [] if url.group().lower().startswith("file:") else [url.group()]
        elif (
            any(dot in operand for dot in ".\u3002\uff0e\uff61")
            or operand == "localhost"
            or BARE_HOST.fullmatch(operand)
            or COMMAND_SUBST.search(operand)
            or WHOLE_VARIABLE.fullmatch(operand)
        ):
            found.append(operand)
    return found


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
        operands = bare + [value for name, value in opts if name == "--url" and value]
        found = targets(operands)
        found += [b for b in operands if b.startswith("$") and b not in found]
        return found, curl_uploads(opts), reroutes(opts) or proxied(cmd) or header_exfil(allow, opts, found)
    if cmd.name == "wget":
        opts, bare = wget_options(cmd.args)
        found = targets(bare)
        return found, wget_uploads(opts), proxied(cmd) or header_exfil(allow, opts, found)
    if cmd.name in POWERSHELL_FETCHERS:
        opts, bare = powershell_options(cmd.args)
        return (
            targets([value for name, value in opts if name == "uri" and value] + bare),
            powershell_uploads(opts),
            None,
        )
    return [], False, None


def upload_verdict(allow: Allowlist, urls: list[str]) -> Verdict:
    """The first upload target outside the allowlist."""
    return next((v for url in urls if (v := unapproved(allow, "uploading data to", url))), None)
