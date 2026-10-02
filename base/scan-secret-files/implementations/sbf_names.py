"""Files that are secrets by their name: key stores, SSH keys, Terraform state, browser stores, dotenv and framework files.

Binary containers are refused on the name alone (their content reaches a gate lossily); the
text-format ones are refused only when they hold a literal value, so a template stays allowed.
"""

from __future__ import annotations

import re

from sbf_core import BROWSER, ENV, FRAMEWORK, KEYS, TF, Finding, line_of, literal, secretish, unquote

KEY_SUFFIXES = (".p12", ".pfx", ".jks", ".keystore", ".jceks", ".p8", ".ppk")
SSH_KEYS = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"})
TFSTATE = re.compile(r"\.tfstate(?:\.[^/]*)?$")
#: Chrome's own file names are case-exact; Firefox's are lower case.
BROWSER_EXACT = frozenset({"Cookies", "Login Data"})
BROWSER_LOWER = frozenset({"cookies.sqlite", "key4.db", "key3.db", "signons.sqlite"})
#: scan-secrets' template words: a dotenv file whose last suffix (or `<word>.env` stem) is one is a template.
TEMPLATE = frozenset({"sample", "example", "template", "dist", "defaults"})
ENV_LINE = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][\w.-]*)[ \t]*=[ \t]*(.*?)[ \t]*$")
INLINE_COMMENT = re.compile(r"[ \t]+#.*$")
TFVAR = re.compile(r'(?m)^[ \t]*([\w-]+)[ \t]*=[ \t]*"([^"\r\n]*)"')
TF_TOKEN = re.compile(r'\btoken[ \t]*=[ \t]*"([^"\r\n]*)"')
RAILS_KEY = re.compile(r"\s*[0-9a-f]{32}\s*")
YAML_PAIR = re.compile(r"(?m)^[ \t]*([\w.-]+)[ \t]*:[ \t]*(.+?)[ \t]*$")
DJANGO = re.compile(
    r"""(?m)^[ \t]*(SECRET_KEY)[ \t]*=[ \t]*(['"])([^'"\r\n]*)\2|(['"])(PASSWORD)\4[ \t]*:[ \t]*(['"])([^'"\r\n]*)\6"""
)


def judge(path: str, name: str, base: str, text: str) -> list[Finding]:
    """`path` uses /, `name` is its last segment lowercased and `base` as written."""
    if not text.strip():
        return []
    found = [*containers(name, base, text)]
    if dotenv(name):
        found += [Finding(ENV, line_of(text, m.start()), f"literal value for {m[1]}", v) for m, v in assignments(text)]
    if name.endswith(".tfvars"):
        found += [
            Finding(TF, line_of(text, m.start()), f"literal value for {m[1]}", m[2])
            for m in TFVAR.finditer(text)
            if secretish(m[1], m[2])
        ]
    if name in (".terraformrc", "terraform.rc"):
        found += [
            Finding(TF, line_of(text, m.start()), "Terraform CLI token", m[1])
            for m in TF_TOKEN.finditer(text)
            if literal(m[1])
        ]
    return found + framework(path, name, text)


def containers(name: str, base: str, text: str) -> list[Finding]:
    """Files refused by their name alone: key stores, SSH private keys, Terraform state, browser stores."""
    if name.endswith(KEY_SUFFIXES) or name in SSH_KEYS:
        return [Finding(KEYS, 1, f"private key file ({base})", text)]
    if TFSTATE.search(name):
        return [Finding(TF, 1, "Terraform state", text)]
    if base in BROWSER_EXACT or name in BROWSER_LOWER:
        return [Finding(BROWSER, 1, f"browser credential store ({base})", text)]
    return []


def dotenv(name: str) -> bool:
    """A dotenv file that is not a template: `.env`, `.env.<x>` (also `-<x>`, `_<x>`), `<x>.env`, `.envrc`."""
    if name in (".env", ".envrc"):
        return True
    if name.startswith((".env.", ".env-", ".env_")):
        return re.split(r"[._-]", name)[-1] not in TEMPLATE
    return name.endswith(".env") and name[: -len(".env")].rsplit(".", 1)[-1] not in TEMPLATE


def assignments(text: str) -> list[tuple[re.Match[str], str]]:
    """Each `KEY=value` whose key is secret-like and whose value is a literal, quotes and a trailing comment off."""
    found = []
    for match in ENV_LINE.finditer(text):
        raw = match[2]
        value = unquote(raw) if raw[:1] in "'\"" else INLINE_COMMENT.sub("", raw)
        if secretish(match[1], value):
            found.append((match, value))
    return found


def framework(path: str, name: str, text: str) -> list[Finding]:
    """Rails master key and secrets.yml, Django local settings; WordPress and appsettings are judged by shape."""
    found = []
    if (name == "master.key" or re.search(r"(^|/)credentials/[^/]+\.key$", path)) and RAILS_KEY.fullmatch(text):
        found.append(Finding(FRAMEWORK, 1, "Rails master key", text))
    if name in ("secrets.yml", "secrets.yaml"):
        found += [
            Finding(FRAMEWORK, line_of(text, m.start()), f"literal value for {m[1]}", m[2])
            for m in YAML_PAIR.finditer(text)
            if secretish(m[1], m[2])
        ]
    if name == "local_settings.py":
        for match in DJANGO.finditer(text):
            key, value = (match[1], match[3]) if match[1] else (match[5], match[7])
            if literal(value) and (key == "PASSWORD" or len(value) >= 8):  # noqa: PLR2004 -- Django's dev keys are short
                found.append(Finding(FRAMEWORK, line_of(text, match.start()), f"Django {key}", value))
    return found
