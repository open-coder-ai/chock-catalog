"""A password encoder that does not hash, or hashes with a broken digest, at all makes login safe
only against a reader who never sees the store."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "spring-weak-password-encoder"

_FACTS = facts("spring")["password_encoder"]

_MESSAGE = (
    "{what} does not protect a stolen password store -- a leaked table of these hashes is either "
    "already plaintext or crackable offline in bulk. Use BCryptPasswordEncoder, Argon2PasswordEncoder "
    "or Pbkdf2PasswordEncoder (DelegatingPasswordEncoder if this store must also read older hashes)."
)


def _guard(text: FileText) -> bool:
    return not ("src/test/" in text.path.replace("\\", "/") or "Test" in text.path.rsplit("/", 1)[-1])


def scan(text: FileText) -> Iterator[Finding]:
    """A weak encoder class, a `{noop}` password literal, or the unencoded default -- outside tests."""
    if not _guard(text):
        return
    for line_no, line in enumerate(text.lines, 1):
        hit = next((token for token in _FACTS["weak_tokens"] if token in line), None)
        if hit is None and _FACTS["noop_literal"] in line and '"' in line:
            hit = _FACTS["noop_literal"]
        if hit is None and _FACTS["default_encoder_user"] in line:
            hit = _FACTS["default_encoder_user"]
        if hit is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(what=hit))


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Weak or absent password encoder",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(hash): NoOpPasswordEncoder|Md5/Sha/Standard/LdapSha/MessageDigestPasswordEncoder|"
        '"{noop}" password|User.withDefaultPasswordEncoder() -- use BCrypt, Argon2 or Pbkdf2'
    ),
    refuses="the no-op and legacy digest encoders, a {noop} literal, and withDefaultPasswordEncoder()"
    " outside test sources",
    silent_on="BCryptPasswordEncoder, Argon2PasswordEncoder, Pbkdf2PasswordEncoder, SCryptPasswordEncoder,"
    " DelegatingPasswordEncoder, a {bcrypt} literal, and test sources",
    cwe=("CWE-256", "CWE-916"),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",),
)
