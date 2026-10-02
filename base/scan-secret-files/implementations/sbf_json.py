"""Secret-bearing JSON by shape, whatever the file is called: Google, kubeconfig, Terraform, registry and browser files.

Read with chock_scan.jsonc (comments and trailing commas allowed) and every duplicate key kept: a
loader keeps only the last, but the file still carries the first.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from chock_scan import entropy, jsonc, keyword_values
from sbf_core import (
    ASK,
    BROWSER,
    FRAMEWORK,
    GCP,
    KUBE,
    KUBE_PROVIDER,
    KUBE_USER,
    NOTEBOOK,
    RC,
    TF,
    Finding,
    key_material,
    line_of,
    literal,
    secretish,
)

#: Large enough for any credential file; a larger JSON file is judged by the other rules only.
LIMIT = 1 << 23
MAX_NODES = 200_000
DOCKER_AUTH = ("auth", "password", "identitytoken", "registrytoken")
COMPOSER = ("http-basic", "github-oauth", "gitlab-token", "gitlab-oauth", "bearer", "bitbucket-oauth", "forgejo-token")
COMPOSER_SECRET = frozenset({"password", "token", "consumer-secret", "access-token"})
CONN_PW = re.compile(r"(?i)(?:^|;)\s*(?:password|pwd)\s*=\s*([^;]*)")


#: A document that opens like JSON: blanks and comments, then an object or array.
#: Blanks and comments, then an object opening on a quoted key (or empty), or an array of objects or
#: strings: not TOML or INI sections, Markdown links or number arrays.
_TRIVIA = r"(?:\s|//[^\n]*+\n|/\*(?:[^*]|\*(?!/))*+\*/)*+"
JSONISH = re.compile(_TRIVIA + r"(?:\{" + _TRIVIA + r"[\"}]|\[" + _TRIVIA + r"[{\"\]\[])")
#: Keys a credential file of each shape carries (all of the first, one of the second); JSON this reader
#: cannot parse that holds them is reported.
MARKERS = (
    (GCP, ('"service_account"', '"private_key"'), ()),
    (GCP, ('"authorized_user"', '"refresh_token"'), ()),
    (GCP, ('"client_secret"',), ('"installed"', '"web"')),
    (TF, ('"terraform_version"', '"lineage"'), ()),
    (RC, ('"auths"',), ('"auth"', '"identitytoken"', '"password"')),
    (KUBE, ('"Config"', '"users"'), ()),
    (BROWSER, ('"encryptedPassword"', '"logins"'), ()),
)


def unreadable(text: str) -> list[Finding]:
    """Fail closed: JSON this reader cannot parse (too deep, too large, malformed) holding a credential file's keys."""
    return [
        Finding(rule, 1, "credential-shaped JSON this reader cannot parse", text)
        for rule, keys, either in MARKERS
        if all(key in text for key in keys) and (not either or any(key in text for key in either))
    ]


class Obj(list):
    """A JSON object as its (key, value) pairs in source order, duplicates kept."""

    def all(self, key: str) -> list[object]:
        return [value for name, value in self if name == key]


def parse(text: str) -> object:
    """The document, objects as Obj; ValueError when it is not JSON (or JSONC) this reader can take."""
    return json.loads(jsonc.strip(text, LIMIT), object_pairs_hook=Obj)


def judge(text: str, name: str = "") -> list[Finding]:
    """Every credential the JSON shapes show; `name` is the lowercased file name, for the name-led rules."""
    if not JSONISH.match(text):
        return []
    try:
        root = parse(text)
    except ValueError:
        root = lines(text)
        if root is None:
            return unreadable(text)
    found = [finding for obj in objects(root) for finding in shapes(obj, text)]
    if isinstance(root, Obj):
        found += notebook(root, text) + legacy_docker(root, text)
        if name.startswith("appsettings.production.") or name.endswith(".tfvars.json"):
            found += named(root, text, FRAMEWORK if name.startswith("appsettings") else TF)
    return found


def lines(text: str) -> list[object] | None:
    """JSON Lines: one document per non-blank line (plain JSON per line), or None when any line is not one."""
    try:
        return [json.loads(line, object_pairs_hook=Obj) for line in text.split("\n") if line.strip()]
    except (ValueError, RecursionError):
        return None


def objects(root: object) -> Iterator[Obj]:
    """Every object in the document, outermost first, at most MAX_NODES nodes."""
    stack, seen = [root], 0
    while stack and seen < MAX_NODES:
        node = stack.pop()
        seen += 1
        if isinstance(node, Obj):
            yield node
            stack.extend(value for _, value in reversed(node))
        elif isinstance(node, list):
            stack.extend(reversed(node))


def at(text: str, key: str) -> int:
    """The line a key is first written on."""
    return line_of(text, text.find(json.dumps(key)))


def shapes(obj: Obj, text: str) -> list[Finding]:
    """Every credential one object's shape shows."""
    return [*google(obj, text), *infra(obj, text), *registries(obj, text), *browser(obj, text)]


def google(obj: Obj, text: str) -> list[Finding]:
    """A service-account key, an authorized-user refresh token, an OAuth client secret."""
    found = []
    kinds = obj.all("type")
    if "service_account" in kinds and any(key_material(v) for v in obj.all("private_key")):
        found.append(Finding(GCP, at(text, "private_key"), "Google service-account private key", text))
    if "authorized_user" in kinds and any(literal(v) for v in obj.all("refresh_token")):
        found.append(Finding(GCP, at(text, "refresh_token"), "Google user refresh token", text))
    for client in (v for key in ("installed", "web") for v in obj.all(key) if isinstance(v, Obj)):
        if any(literal(v) for v in client.all("client_secret")):
            found.append(Finding(GCP, at(text, "client_secret"), "Google OAuth client secret", text))
    return found


def infra(obj: Obj, text: str) -> list[Finding]:
    """A kubeconfig in JSON, Terraform state, a Terraform CLI credentials file."""
    found = []
    if "Config" in obj.all("kind"):
        found += [Finding(KUBE, at(text, key), f"kubeconfig user {key}", text) for key in kube_users(obj)]
    if all(obj.all(key) for key in ("terraform_version", "lineage", "serial")):
        found.append(Finding(TF, 1, "Terraform state", text))
    for host, entry in hosts(obj, "credentials"):
        if isinstance(entry, Obj) and any(literal(v) for v in entry.all("token")):
            found.append(Finding(TF, at(text, host), "Terraform CLI token", text))
    return found


def registries(obj: Obj, text: str) -> list[Finding]:
    """A docker config login, a Composer auth section."""
    found = []
    for host, entry in hosts(obj, "auths"):
        if isinstance(entry, Obj) and any(literal(v) for key in DOCKER_AUTH for v in entry.all(key)):
            found.append(Finding(RC, at(text, host), "registry login", text))
    for key in COMPOSER:
        if any(composer_secret(section) for section in obj.all(key)):
            found.append(Finding(RC, at(text, key), f"Composer {key} credential", text))
    return found


def browser(obj: Obj, text: str) -> list[Finding]:
    """Firefox's logins.json: saved logins with their encrypted passwords (the key to decrypt them sits beside it)."""
    found = []
    for logins in obj.all("logins"):
        if isinstance(logins, list) and any(
            isinstance(item, Obj) and any(literal(v) for v in item.all("encryptedPassword")) for item in logins
        ):
            found.append(Finding(BROWSER, at(text, "logins"), "browser saved logins", text))
    return found


def hosts(obj: Obj, key: str) -> list[tuple[str, object]]:
    """The (host, entry) pairs of every object under `key`."""
    return [pair for section in obj.all(key) if isinstance(section, Obj) for pair in section]


def legacy_docker(root: Obj, text: str) -> list[Finding]:
    """A legacy .dockercfg: a document whose every key is a registry host with an `auth` entry."""
    if not root or not all("." in host or ":" in host for host, _ in root):
        return []
    return [
        Finding(RC, at(text, host), "registry login", text)
        for host, entry in root
        if isinstance(entry, Obj) and any(literal(v) for v in entry.all("auth"))
    ]


def kube_users(obj: Obj) -> list[str]:
    """The credential keys a kubeconfig object's users carry inline."""
    found = []
    for users in obj.all("users"):
        for item in users if isinstance(users, list) else []:
            for user in item.all("user") if isinstance(item, Obj) else []:
                if not isinstance(user, Obj):
                    continue
                found += [key for key, value in user if key in KUBE_USER and literal(value)]
                for provider in (p for p in user.all("auth-provider") if isinstance(p, Obj)):
                    for config in (c for c in provider.all("config") if isinstance(c, Obj)):
                        found += [key for key, value in config if key in KUBE_PROVIDER and literal(value)]
    return found


def composer_secret(section: object) -> bool:
    """A Composer auth section holding a token or password: `host: token` or `host: {password|token: ...}`."""
    if not isinstance(section, Obj):
        return False
    for _, entry in section:
        if literal(entry):
            return True
        if isinstance(entry, Obj) and any(key in COMPOSER_SECRET and literal(value) for key, value in entry):
            return True
    return False


def notebook(root: Obj, text: str) -> list[Finding]:
    """A Jupyter notebook's outputs holding a high-entropy keyword value (asks: outputs are noisy).

    A private key in an output is refused by sbf_keys, which reads the raw file.
    """
    if not root.all("nbformat"):
        return []
    found = []
    for out in outputs(root):
        if any(entropy.assess(c.value).suspicious for c in keyword_values.candidates(out)):
            found.append(Finding(NOTEBOOK, at(text, "outputs"), "notebook output holding a secret", out, ASK))
    return found


def outputs(root: Obj) -> Iterator[str]:
    """The text of every cell output: stream text and text/plain data, joined when given as a list."""
    for cells in root.all("cells"):
        for cell in cells if isinstance(cells, list) else []:
            for outs in cell.all("outputs") if isinstance(cell, Obj) else []:
                for out in outs if isinstance(outs, list) else []:
                    if not isinstance(out, Obj):
                        continue
                    data = [d for d in out.all("data") if isinstance(d, Obj)]
                    for value in [*out.all("text"), *(v for d in data for v in d.all("text/plain"))]:
                        parts = value if isinstance(value, list) else [value]
                        joined = [part for part in parts if isinstance(part, str)]
                        if joined:
                            yield "".join(joined)


def named(root: Obj, text: str, rule: str) -> list[Finding]:
    """A settings or variables file: every secret-like key holding a literal, and connection-string passwords."""
    found = []
    for obj in objects(root):
        for key, value in obj:
            if not isinstance(value, str):
                continue
            conn = CONN_PW.search(value)
            if secretish(key, value) or (conn and literal(conn[1])):
                found.append(Finding(rule, at(text, key), f"literal value for {key}", value))
    return found
