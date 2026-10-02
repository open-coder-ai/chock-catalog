"""Where a locked package is fetched from, judged against the ecosystem's registry hosts and the repo's allowlist.

Hosts are compared after the shared EP11 normaliser (chock_scan.urls/hostmatch): case, IDN, trailing-dot and
numeric-address spellings of one host match it, and a URL that parsers split differently is refused, never read
one way. No name is resolved (no DNS, no network).
"""

from __future__ import annotations

import re

from chock_scan.hostmatch import Entry as HostEntry
from chock_scan.hostmatch import matches, parse_allowlist, parse_entry
from chock_scan.hosts import UnparseableError
from chock_scan.urls import parse_url

#: The registries each ecosystem's own client uses by default. Anything else is named in the allowlist file.
DEFAULT_HOSTS = {
    "npm": ("registry.npmjs.org", "registry.yarnpkg.com"),
    "pypi": ("pypi.org", "files.pythonhosted.org"),
    "cargo": ("index.crates.io", "static.crates.io"),
    "gem": ("rubygems.org", "index.rubygems.org"),
    # Packagist serves most dist archives as GitHub zipballs, so the GitHub API and archive hosts are its default.
    "composer": ("repo.packagist.org", "packagist.org", "api.github.com", "codeload.github.com"),
}
DEFAULTS = {eco: tuple(parse_entry(host) for host in hosts) for eco, hosts in DEFAULT_HOSTS.items()}
ALLOWLIST = ".chock/registry-allowlist.txt"
SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):")
HTTPS_PORT = 443


def load_allowlist(text: str | None) -> tuple[tuple[HostEntry, ...], str]:
    """(entries, problem): the committed allowlist's entries, or none and why when it cannot be read."""
    if not text:
        return (), ""
    try:
        return parse_allowlist(text), ""
    except UnparseableError as exc:
        return (), f"{ALLOWLIST} could not be read ({exc}), so only the default registries count"


def _url_problem(url_text: str) -> str:
    """Why an https URL cannot be trusted as written, or '' with the host left to the caller."""
    try:
        url = parse_url(url_text)
    except UnparseableError as exc:
        return f"a URL that parsers read differently ({exc})"
    if url.userinfo:
        return "a URL carrying credentials"
    if url.port != HTTPS_PORT:
        return f"a URL on port {url.port}, not the registry's"
    return ""


def scheme_of(source: str) -> str:
    found = SCHEME.match(source)
    return found.group(1).lower() if found else ""


def host_of(source: str) -> str:
    """The normalised host of an https URL, for keys and messages; '' when it has none."""
    try:
        return parse_url(source).host.name
    except UnparseableError:
        return ""


def problem(source: str, eco: str, allow: tuple[HostEntry, ...], *, git: bool = False) -> str:
    """Why `source` is not an https URL on a registry host (any https host for a git source), or ''."""
    scheme = scheme_of(source)
    url = source[4:] if git and scheme == "git+https" else source
    if scheme_of(url) != "https":
        return f"fetched with {scheme}: (only https is accepted)" if scheme else "not a URL (an ssh or local path)"
    if why := _url_problem(url):
        return why
    if git:
        return ""
    host = parse_url(url).host
    if any(matches(host, entry) for entry in (*DEFAULTS.get(eco, ()), *allow)):
        return ""
    return f"fetched from {host.name}, which is neither a default {eco} registry nor listed in {ALLOWLIST}"
