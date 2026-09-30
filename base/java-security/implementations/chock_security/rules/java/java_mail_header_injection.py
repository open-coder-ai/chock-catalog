"""A JavaMail header built from request data can carry \\r\\n and smuggle in extra SMTP headers
-- a Bcc: the sender never wrote, or an entirely separate message tacked onto the first."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-mail-header-injection"

_FACTS = facts("java")["mail_injection"]

_MESSAGE = (
    "This mail header is built from {source}, so the caller can inject \\r\\n and add SMTP "
    "headers this code never sent -- a forged Bcc, a spoofed From, or a whole second message. "
    "Strip control characters before the value reaches this call, or build the address with "
    f"InternetAddress(value, true), which rejects one. A value already validated needs "
    f"'chock: allow {RULE_ID}' on this line."
)


def _guarded(text: FileText) -> bool:
    """Only files that actually use JavaMail -- the sink names alone are too generic to trust."""
    return text.holds(*_FACTS["guard_imports"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every Message header setter a method body shows request data reaching, in a JavaMail file."""
    if not _guarded(text):
        return
    for flow in flows(text, _FACTS["sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Mail header built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(call): Message.setSubject|setFrom|setReplyTo|addRecipient(s)|setRecipient(s) "
        "built from @RequestParam|@PathVariable|request.get* in a file using javax.mail/"
        "jakarta.mail -- strip control characters first, or use InternetAddress(value, true)"
    ),
    refuses=(
        "a setSubject/setFrom/setReplyTo/addRecipient(s)/setRecipient(s) call a method body "
        "shows request data reaching, in a file that imports javax.mail or jakarta.mail"
    ),
    silent_on=(
        "a constant subject/address; the same call in a file with no javax.mail/jakarta.mail "
        "import; an address built through InternetAddress(value, true), which rejects control characters"
    ),
    cwe=("CWE-93",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",),
)
