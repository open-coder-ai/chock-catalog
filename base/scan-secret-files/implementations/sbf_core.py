"""What every scan-secret-files rule shares: the finding, the rule ids, and when a credential slot holds a real value."""

from __future__ import annotations

import bisect
import functools
import re
from typing import NamedTuple

from chock_scan import keyword_values

BLOCK, ASK = "block", "ask"
GCP = "sbf-gcp-sa-json"
KUBE = "sbf-kubeconfig"
TF = "sbf-tfstate-tfvars"
RC = "sbf-rc-credentials"
KEYS = "sbf-private-key-files"
AWS = "sbf-aws-credentials"
ENV = "sbf-tracked-env"
FRAMEWORK = "sbf-framework-secrets"
NOTEBOOK = "sbf-notebook-outputs"
BROWSER = "sbf-browser-credential-stores"
#: Credential keys of a kubeconfig user, and of its auth-provider config.
KUBE_USER = frozenset({"token", "client-key-data", "password"})
KUBE_PROVIDER = frozenset({"client-secret", "refresh-token", "id-token", "access-token"})
#: Base64 characters a private key body must carry: a PKCS#8 Ed25519 key, the smallest, has 64.
MIN_BODY = 40


class Finding(NamedTuple):
    """One secret-bearing file or slot; `value` keys the finding (hashed) and is never printed."""

    rule: str
    line: int
    what: str
    value: str
    level: str = BLOCK


#: A value that names where the secret lives instead of holding it: an env lookup, a template, a vault.
REFERENCE = re.compile(
    r"(?i)\s*(?:\$\{|\$\(|\$[a-z_]|%[a-z_]\w*%|\{\{|\{%|<%|enc\[|vault:|ref\+|op://|!(?:ref|sub|getatt)\b|#\{|\(\(|"
    r"(?:os\.)?environ\b|(?:os\.|system\.)?getenv\s*\(|process\.env\b|env\[|env\()"
)
#: Template words: a value holding one is documentation, not a credential (as chock_scan.entropy judges).
PLACEHOLDER = re.compile(
    r"(?i)example|sample|placeholder|changeme|change[_-]me|dummy|redacted|notreal|not[_-]a[_-]real|your[_-]|"
    r"insert[_-]|replace[_-]?me|xxxx|\*\*\*\*|\.\.\.|lorem|foobar|todo|password[_-]here|unique phrase|^<.*>$"
)
REPEAT = re.compile(r"(.)\1*")
NUMBER_OR_FLAG = re.compile(r"(?i)[-+]?\d+(?:\.\d+)?[a-z]{0,2}|true|false|yes|no|on|off|null|none|nil")
ARMOR = re.compile(r"-----(?:BEGIN|END) [^-\r\n]{1,60}-----")
BASE64 = re.compile(r"[A-Za-z0-9+/=]")


def unquote(value: str) -> str:
    """The value without surrounding blanks and one pair of matching quotes."""
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":  # noqa: PLR2004 -- a quote pair
        return text[1:-1].strip()
    return text


def literal(value: object) -> bool:
    """A non-empty string that is no reference, template word or one repeated character."""
    if not isinstance(value, str):
        return False
    text = unquote(value)
    return bool(text) and not REFERENCE.match(text) and not PLACEHOLDER.search(text) and not REPEAT.fullmatch(text)


def secretish(key: str, value: str, minimum: int = 8) -> bool:
    """A secret-like key (chock_scan.keyword_values) holding a literal of `minimum`+ characters, not a number or flag."""
    text = unquote(value)
    return (
        keyword_values.secret_key(key) and literal(text) and len(text) >= minimum and not NUMBER_OR_FLAG.fullmatch(text)
    )


def key_material(value: object) -> bool:
    """A private-key slot holding key bytes: MIN_BODY base64 characters once armor and headers are dropped.

    Template words are not looked for: a real key body is random enough to spell one.
    """
    if not isinstance(value, str) or REFERENCE.match(value):
        return False
    return body_size(value) >= MIN_BODY


def body_size(block: str) -> int:
    """Base64 characters of a key block, its armor lines and `Name: value` headers left out."""
    lines = ARMOR.sub("\n", block.replace("\\n", "\n")).splitlines()
    return sum(len(BASE64.findall(line)) for line in lines if ":" not in line)


def line_of(text: str, pos: int) -> int:
    """The 1-based line of an offset; an offset not found (-1) is line 1. Logarithmic after one pass per text."""
    return bisect.bisect_left(_breaks(text), max(pos, 0)) + 1


@functools.lru_cache(maxsize=4)
def _breaks(text: str) -> list[int]:
    return [match.start() for match in re.finditer("\n", text)]
