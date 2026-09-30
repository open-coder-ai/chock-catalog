"""An LDAP filter is text the directory parses; an unescaped value can close it and add clauses."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-ldap-injection"

_FACTS = facts("java")["ldap"]

_MESSAGE = (
    "This search filter is built from {source}, so a value containing '*' or ')' changes which "
    "clause the directory reads, not just which value it matches -- an authentication bypass in "
    "the common case. Escape the value with LdapEncoder.filterEncode before it reaches the "
    "filter, or build the query with Spring LDAP's query()/.is() form, which escapes for you. A "
    f"filter that must stay dynamic needs 'chock: allow {RULE_ID}' on this line, with that "
    "escaping in place."
)


def _uses_ldap(text: FileText) -> bool:
    """This rule reads only files that import the LDAP APIs -- elsewhere `.search()` belongs to
    countless unrelated repositories and search engines this rule has no business judging."""
    return text.holds(*_FACTS["imports"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every DirContext/LdapTemplate search a method body shows request data reaching unescaped."""
    if not _uses_ldap(text):
        return
    for flow in flows(text, _FACTS["sinks"], sanitizers=tuple(_FACTS["sanitizers"])):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="LDAP filter built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(search): DirContext|InitialDirContext|LdapTemplate .search( over "
        "@RequestParam|@PathVariable|request.get* -- escape with LdapEncoder.filterEncode, or "
        "build the query with Spring LDAP's query()/.is()"
    ),
    refuses=(
        "a `DirContext`/`InitialDirContext`/`LdapTemplate` `.search()` a method body shows "
        "request data reaching unescaped, in a file that imports the LDAP APIs"
    ),
    silent_on=(
        "the same search over a value passed through `LdapEncoder`; Spring LDAP's query builder "
        "with `.is()`; a constant filter; `.search()` in a file with no LDAP import"
    ),
    cwe=("CWE-90",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",),
)
