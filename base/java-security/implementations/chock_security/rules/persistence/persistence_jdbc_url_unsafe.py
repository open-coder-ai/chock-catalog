"""A JDBC URL parameter can turn the driver itself into the attacker's tool."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "persistence-jdbc-url-unsafe"

_FACTS = facts("persistence")["jdbc_url"]

_MESSAGE = (
    "This JDBC URL sets `{flag}`, which {why}. Remove it (or set the safe value) so the driver "
    f"cannot be turned against the application that opens it. A URL that must carry it needs "
    f"'chock: allow {RULE_ID}' on this line and a note on why this connection is trusted."
)

_WHY = {
    "autoDeserialize=true": "lets the server hand the driver a serialized Java object to deserialize on connect",
    "allowLoadLocalInfile=true": "lets a compromised or spoofed server read arbitrary local files through LOAD DATA LOCAL",
    "allowUrlInLocalInfile=true": "lets LOAD DATA LOCAL read from a URL, including the local filesystem",
    "allowPublicKeyRetrieval=true": "lets the server hand back an RSA public key it claims is its own, defeating auth",
    "useSSL=false": "sends credentials and query results in the clear",
    "sslMode=DISABLED": "sends credentials and query results in the clear",
    "sslmode=disable": "sends credentials and query results in the clear",
    "trustServerCertificate=true": "accepts any server certificate, so a network attacker can impersonate the database",
    "encrypt=false": "sends credentials and query results in the clear",
    "verifyServerCertificate=false": "accepts any server certificate, so a network attacker can impersonate the database",
}


def _is_local(line: str) -> bool:
    return any(host in line for host in _FACTS["local_hosts"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every unsafe flag on a JDBC URL, remote-only ones excused for a local-only host."""
    if _FACTS["test_path_marker"] in text.path:
        return
    local = None
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["marker"] not in line:
            continue
        if local is None:
            local = _is_local(line)
        flag = next((f for f in _FACTS["always_unsafe"] if f in line), None)
        if flag is None and not local:
            flag = next((f for f in _FACTS["remote_unsafe"] if f in line), None)
        if flag is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(flag=flag, why=_WHY[flag]))


RULE = Rule(
    id=RULE_ID,
    pack="persistence",
    title="Unsafe JDBC URL parameter",
    suffixes=(".java", ".kt", ".properties", ".yml", ".yaml", ".xml"),
    scan=scan,
    constraint=(
        "never(set): a jdbc: URL with autoDeserialize=true|allowLoadLocalInfile=true|"
        "allowUrlInLocalInfile=true|allowPublicKeyRetrieval=true|useSSL=false|sslMode=DISABLED|"
        "sslmode=disable|trustServerCertificate=true|encrypt=false|verifyServerCertificate=false "
        "-- remove the flag or set its safe value"
    ),
    refuses=(
        "a jdbc: URL setting autoDeserialize, allowLoadLocalInfile or allowUrlInLocalInfile "
        "anywhere, or the TLS-weakening flags (useSSL=false, sslMode=DISABLED, "
        "trustServerCertificate=true, encrypt=false, allowPublicKeyRetrieval=true, "
        "verifyServerCertificate=false) against a non-local host"
    ),
    silent_on=(
        "the TLS-weakening flags against localhost/127.0.0.1/an in-memory H2 database, "
        "and any of these flags under src/test/"
    ),
)
