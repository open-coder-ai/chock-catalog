"""A password or secret written as a plain value in application config ships with every build,
every checkout, and every backup of the repository -- forever, not just until it is rotated."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.spring._config import config_pairs, is_spring_config_file, is_test_resource, key_ends_with

RULE_ID = "spring-plaintext-secret-property"

_FACTS = facts("spring")["secret_property"]

_MESSAGE = (
    "`{key}` is set to a literal value here, so it ships in the built artifact and every checkout "
    "of this file. Reference it from the environment or a secret store instead: "
    "${{{key_var}}} resolved from an environment variable, or a config-server value encrypted with "
    "{{cipher}}. A value this file must carry needs 'chock: allow {rule}' on this line naming why "
    "it is safe here (a local-only profile, a placeholder never meant to work)."
)


#: A switch or a size is configuration about a secret, never the secret: `app.token=true`,
#: `jwt.secret-length=256`. Judged on the value, because the key names the subject either way.
_NOT_A_SECRET = frozenset({"true", "false", "yes", "no", "on", "off", "none", "null"})


def _is_safe_value(value: str) -> bool:
    if not value or value.lower() in _NOT_A_SECRET or value.isdigit():
        return True
    return any(value.startswith(prefix) for prefix in _FACTS["safe_value_prefixes"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every secret-shaped key set to a literal value, outside test resources."""
    if not is_spring_config_file(text.path) or is_test_resource(text.path):
        return
    for entry in config_pairs(text):
        if not key_ends_with(entry.key, *_FACTS["suffixes"]):
            continue
        if _is_safe_value(entry.value):
            continue
        message = _MESSAGE.format(key=entry.key, key_var=entry.key.upper().replace(".", "_"), rule=RULE_ID)
        yield Finding(RULE_ID, text.path, entry.line_no, text.lines[entry.line_no - 1], message)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Plaintext secret in application config",
    suffixes=(".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        "never(set): a *.password|*secret|*.token|*.api-key|*.private-key|*.credentials key to a "
        "literal in application*/bootstrap* config -- reference ${ENV_VAR} or a {cipher} value instead"
    ),
    refuses="a secret-shaped key set to a non-empty literal in main application/bootstrap config",
    silent_on="an empty value; a boolean or number; a ${...} placeholder; a {cipher}/ENC()/vault:/sm:// reference; test resources",
    cwe=("CWE-798", "CWE-256"),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",),
)
