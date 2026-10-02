"""Data hidden in the destination (GET and DNS exfiltration), interpreter HTTP one-liners, writes that rewire curl or wget."""

from __future__ import annotations

import re

from chock_shellparse import Cmd, writes_files
from egress_core import ASK_PERSON, COMMAND_SUBST, VARIABLE, Allowlist, Verdict, confirm, permitted, refuse

WHOLE_VARIABLE = re.compile(r"\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})")
SINGLE_QUOTED = re.compile(r"'[^']*'")
DNS_TOOLS = ("ping", "ping6", "nslookup", "dig", "host", "traceroute", "tracepath", "mtr", "drill")
CLIENTS = (*DNS_TOOLS, "curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod")
BACKTICK_CLIENT = re.compile(
    rf"(?:^|[;&|(\n])\s*(?:\w+=\S+\s+)*(?:sudo\s+)?(?:\S*/)?(?:{'|'.join(CLIENTS)})(?:\.exe)?\s[^\n;&|]*`",
    re.IGNORECASE,
)
INTERPRETER = re.compile(r"(?:python[\d.]*|node(?:js)?|ruby|perl|php|deno|bun)(?:\.exe)?")
CODE_FLAGS = frozenset(("-c", "-e", "-E", "-pe", "-ne", "-r", "--eval", "--print", "-p"))
HTTP_LIBS = re.compile(
    r"\b(?:requests|urllib\d?|http\.client|httplib2?|httpx|aiohttp|fetch(?=\s*\()|axios|XMLHttpRequest|node-fetch|superagent)\b"
    r"|Net::HTTP|LWP|HTTP::Tiny|open-uri|socket|http\.request|https\.request|urlopen|curl_init|file_get_contents\(\s*['\"]https?",
    re.IGNORECASE,
)
CLIENT_RC = re.compile(r"(?:^|/)[._]?(?:curlrc|wgetrc)$", re.IGNORECASE)
ALLOWLIST_FILE = re.compile(r"(?:^|/)\.chock/egress-allowlist\.txt$", re.IGNORECASE)
HIDE = "Move the substitution out of the destination, or ask the person."


def authority_and_rest(target: str) -> tuple[str, str]:
    body = target.split("://", 1)[-1] if "://" in target else target.removeprefix("//")
    match = re.search(r"[/?#]", body)
    return (body[: match.start()], body[match.start() :]) if match else (body, "")


def hidden_in_host(text: str) -> Verdict:
    """Command substitution or a variable joined to other text in a host: the name carries data out through DNS."""
    host = text.rsplit("@", 1)[-1]
    if COMMAND_SUBST.search(host) or (VARIABLE.search(host) and not WHOLE_VARIABLE.fullmatch(host)):
        return refuse(
            f"a command substitution or variable inside the hostname '{host[:60]}' sends data out in the name. {HIDE}"
        )
    if WHOLE_VARIABLE.fullmatch(host):
        return confirm(f"the host '{host}' comes from a variable this guard cannot read. {ASK_PERSON}")
    return None


def get_exfil(allow: Allowlist, urls: list[str]) -> Verdict:
    """A substitution in a URL's host (always) or in its path or query when the host is not allowlisted."""
    for url in urls:
        authority, rest = authority_and_rest(url)
        verdict = hidden_in_host(authority)
        if verdict:
            return verdict
        if (COMMAND_SUBST.search(rest) or VARIABLE.search(rest)) and not permitted(allow, url):
            return refuse(
                f"a command substitution or variable in the URL path or query of '{authority[:60]}' puts data in a GET. {HIDE}"
            )
    return None


def dns_exfil(cmd: Cmd) -> Verdict:
    """ping, nslookup, dig, host and the like with a substitution in the name they resolve."""
    if cmd.name not in DNS_TOOLS:
        return None
    return next((v for arg in cmd.args if not arg.startswith("-") and (v := hidden_in_host(arg))), None)


def backtick_client(raw: str) -> Verdict:
    """An unquoted backtick on a network client's line: the parser ends the word there, so the URL is not seen whole."""
    if BACKTICK_CLIENT.search(SINGLE_QUOTED.sub("''", raw)):
        return refuse(f"a backtick substitution on a network command can put data in its destination. {HIDE}")
    return None


def interpreter_http(cmd: Cmd) -> Verdict:
    """python -c, node -e, ruby -e, perl -e (or a heredoc to them) that use an HTTP client: opaque, so ask."""
    name = cmd.name.rsplit("/", 1)[-1].lower()
    if not INTERPRETER.fullmatch(name):
        return None
    code = " ".join(cmd.args) if CODE_FLAGS & set(cmd.args) else ""
    if HTTP_LIBS.search(f"{code}\n{cmd.doc}"):
        return confirm(
            f"'{name}' code that talks over the network can send anything anywhere; this guard cannot read it. {ASK_PERSON}"
        )
    return None


def rewires_clients(cmd: Cmd) -> Verdict:
    """A write to ~/.curlrc, ~/.wgetrc (a default proxy or destination for every later call) or the allowlist file."""
    if writes_files(cmd, lambda path: bool(CLIENT_RC.search(path))):
        return refuse(
            "writing ~/.curlrc or ~/.wgetrc changes where every later curl or wget sends data. Ask the person to edit it."
        )
    if writes_files(cmd, lambda path: bool(ALLOWLIST_FILE.search(path))):
        return refuse("only a person edits .chock/egress-allowlist.txt: the agent must not widen its own egress list.")
    return None
