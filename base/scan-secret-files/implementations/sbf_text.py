"""Credential files in text formats, by shape whatever their name: rc files, AWS and PyPI INI, XML, PHP, kubeconfig.

A name-led file (`.npmrc`, `.netrc`, ...) is read whatever it holds; any other file only when its
whole shape is that format's, so a rename does not hide it and prose that mentions it is not judged.
"""

from __future__ import annotations

import re
from itertools import pairwise

from chock_scan import sniff, yamlpath
from sbf_core import AWS, FRAMEWORK, KUBE, KUBE_PROVIDER, KUBE_USER, RC, Finding, line_of, literal, unquote

AWS_NAMES = ("/.aws/credentials", "/.aws/config")
AWS_KEY = re.compile(r"(?im)^[ \t]*(aws_secret_access_key|aws_session_token)[ \t]*[=:][ \t]*(.*?)[ \t]*$")
SECTION = re.compile(r"(?m)^[ \t]*\[[^\]\r\n]+\][ \t]*$")
PYPI_SECTION = re.compile(r"(?m)^[ \t]*\[(?:distutils|pypi|testpypi)\][ \t]*$")
PYPI_PW = re.compile(r"(?m)^[ \t]*password[ \t]*[=:][ \t]*(.*?)[ \t]*$")
NPM_SCOPED = re.compile(r"(?m)^[ \t]*//[^\s=]+:_(?:authToken|auth|password)[ \t]*=[ \t]*(.*?)[ \t]*$")
NPM_ANY = re.compile(r"(?m)^[ \t]*(?://[^\s=]+:)?_(?:authToken|auth|password)[ \t]*=[ \t]*(.*?)[ \t]*$")
WORD = re.compile(r"\S+")
CRED_URL = re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^\s/:@]*:([^\s/@]+)@\S+")
PGPASS_SPLIT = re.compile(r"(?<!\\):")
NUGET_ADD = re.compile(r"<add\b[^>]{0,2000}>", re.IGNORECASE)
ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(["'])(.*?)\2""")
MAVEN_SECRET = re.compile(r"<(password|passphrase)>([^<]{0,4096})</\1>")
WP_DEFINE = re.compile(
    r"""define\s*\(\s*(['"])(DB_PASSWORD|(?:SECURE_)?AUTH_(?:KEY|SALT)|LOGGED_IN_(?:KEY|SALT)|NONCE_(?:KEY|SALT))\1"""
    r"""\s*,\s*(['"])([^'"\r\n]*)\3"""
)
KIND_CONFIG = re.compile(r"""(?m)^kind[ \t]*:[ \t]*["']?Config["']?[ \t]*(?:#.*)?$""")
SCALARS = frozenset({"plain", "single", "double", "literal", "folded"})


def judge(path: str, name: str, text: str) -> list[Finding]:
    """Every credential the text formats show; `path` uses /, `name` is its lowercased last segment."""
    return [
        *aws(path, text),
        *pypirc(name, text),
        *npmrc(name, text),
        *netrc(name, text),
        *git_credentials(name, text),
        *pgpass(name, text),
        *xml(text),
        *wp_config(text),
        *kubeconfig(text),
    ]


def aws(path: str, text: str) -> list[Finding]:
    """An AWS shared-credentials file: a section and a literal secret key or session token."""
    named = ("/" + path.lower()).endswith(AWS_NAMES)
    if not (named or SECTION.search(text)):
        return []
    return [
        Finding(AWS, line_of(text, m.start()), m[1].lower(), m[2])
        for m in AWS_KEY.finditer(text)
        if literal(m[2]) and len(unquote(m[2])) >= 16  # noqa: PLR2004 -- shorter than any AWS secret
    ]


def pypirc(name: str, text: str) -> list[Finding]:
    """A .pypirc (by name, or by its distutils/pypi section) holding a literal password."""
    if name not in (".pypirc", "pypirc") and not PYPI_SECTION.search(text):
        return []
    return [
        Finding(RC, line_of(text, m.start()), "PyPI password", m[1]) for m in PYPI_PW.finditer(text) if literal(m[1])
    ]


def npmrc(name: str, text: str) -> list[Finding]:
    """npm auth (`_authToken`, `_auth`, `_password`) in an .npmrc; elsewhere only the registry-scoped `//host/:` form."""
    pattern = NPM_ANY if name in (".npmrc", "npmrc") else NPM_SCOPED
    return [
        Finding(RC, line_of(text, m.start()), "npm registry auth", m[1])
        for m in pattern.finditer(text)
        if literal(m[1])
    ]


def netrc(name: str, text: str) -> list[Finding]:
    """A netrc `password` token; a file not named so must open with `machine`/`default` and carry `login`."""
    words = list(WORD.finditer(text))
    if name not in (".netrc", "_netrc", "netrc") and not (
        words and words[0][0] in ("machine", "default") and any(w[0] == "login" for w in words)
    ):
        return []
    return [
        Finding(RC, line_of(text, b.start()), "netrc password", b[0])
        for a, b in pairwise(words)
        if a[0] == "password" and literal(b[0])
    ]


def git_credentials(name: str, text: str) -> list[Finding]:
    """git's credential store: URLs with a password; a file not named so must hold nothing else."""
    rows = [(n, line.strip()) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    matches = [(n, CRED_URL.fullmatch(line)) for n, line in rows]
    if not rows or (name not in (".git-credentials", "git-credentials") and not all(m for _, m in matches)):
        return []
    return [Finding(RC, n, "git credential-store password", m[1]) for n, m in matches if m and literal(m[1])]


def pgpass(name: str, text: str) -> list[Finding]:
    """A PostgreSQL password file: host:port:db:user:password lines."""
    if name not in (".pgpass", "pgpass", "pgpass.conf"):
        return []
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        fields = PGPASS_SPLIT.split(line.strip())
        if not line.lstrip().startswith("#") and len(fields) == 5 and literal(fields[4]):  # noqa: PLR2004 -- the format's fields
            found.append(Finding(RC, number, "pgpass password", fields[4]))
    return found


def xml(text: str) -> list[Finding]:
    """NuGet ClearTextPassword under packageSourceCredentials; Maven settings passwords not `${...}` or `{encrypted}`."""
    found = []
    if "<packagesourcecredentials" in text.lower():
        for tag in NUGET_ADD.finditer(text):
            attrs = {key.lower(): value for key, _, value in ATTR.findall(tag[0])}
            if attrs.get("key", "").lower() == "cleartextpassword" and literal(attrs.get("value")):
                found.append(Finding(RC, line_of(text, tag.start()), "NuGet ClearTextPassword", tag[0]))
    if "<settings" in text and "<server" in text:
        for match in MAVEN_SECRET.finditer(text):
            value = match[2].strip()
            if literal(value) and not (value.startswith("{") and value.endswith("}")):
                found.append(Finding(RC, line_of(text, match.start()), f"Maven settings {match[1]}", value))
    return found


def wp_config(text: str) -> list[Finding]:
    """A WordPress config defining the database password or a salt as a literal (the sample's words are templates)."""
    return [
        Finding(FRAMEWORK, line_of(text, m.start()), f"WordPress {m[2]}", m[4])
        for m in WP_DEFINE.finditer(text)
        if literal(m[4])
    ]


def kubeconfig(text: str) -> list[Finding]:
    """A kubeconfig (root `kind: Config`, found by EP13 sniffing or the line itself) with inline user credentials.

    Fails closed: a file with a `kind: Config` line this reader cannot parse, or whose users sit behind
    an alias or merge key, is reported rather than passed.
    """
    stated = KIND_CONFIG.search(text) is not None
    if not stated and not ("kind" in text and "users" in text and "kubernetes" in sniff.sniff(_bytes(text)).kinds()):
        return []
    try:
        nodes = yamlpath.scan(text)
    except yamlpath.ParseError:
        return [Finding(KUBE, 1, "kubeconfig this reader cannot parse", text)] if stated else []
    configs = {n.doc for n in nodes if n.path == ("kind",) and n.value == "Config"}
    found = [
        Finding(KUBE, n.line, f"kubeconfig user {n.path[-1]}", n.value)
        for n in nodes
        if n.doc in configs and n.kind in SCALARS and _credential(n.path) and literal(n.value)
    ]
    if configs and not found and yamlpath.unknown(nodes, ("users",)):
        found.append(Finding(KUBE, 1, "kubeconfig users behind an alias or merge key", text))
    return found


def _credential(path: tuple[str | int, ...]) -> bool:
    if len(path) < 4 or path[0] != "users" or not isinstance(path[1], int) or path[2] != "user":  # noqa: PLR2004
        return False
    if len(path) == 4:  # noqa: PLR2004 -- users[i].user.<key>
        return path[3] in KUBE_USER
    return len(path) == 6 and path[3:5] == ("auth-provider", "config") and path[5] in KUBE_PROVIDER  # noqa: PLR2004


def _bytes(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass")
