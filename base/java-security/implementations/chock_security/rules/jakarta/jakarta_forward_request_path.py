"""A dispatcher path built from request data can forward the caller straight into WEB-INF."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts
from chock_security.rules.jakarta._config import not_spring

RULE_ID = "jakarta-forward-request-path"

_FACTS = facts("jakarta")["forward"]

_MESSAGE = (
    "This dispatcher path is built from {source}, so the caller chooses which internal resource "
    "is forwarded to -- including compiled JSPs and files under WEB-INF that are never mapped "
    "for direct access. Map the request to a fixed path with a lookup table (an enum or a "
    f"switch over known names), never the raw value. A path that must stay dynamic needs "
    f"'chock: allow {RULE_ID}' on this line, justified by that lookup."
)


def _guarded(text: FileText) -> bool:
    """Only Servlet-family files -- request.getRequestDispatcher is Servlet API, not Spring's."""
    return not_spring(text) and text.holds(*_FACTS["guard_imports"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every getRequestDispatcher call a method body shows request data reaching."""
    if not _guarded(text):
        return
    for flow in flows(text, _FACTS["sinks"], sanitizers=tuple(_FACTS["sanitizers"])):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="Server-side forward to a request-chosen path",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(forward): getRequestDispatcher(...) built from @QueryParam|@PathParam|request.get* "
        "-- map the request to a fixed path with a lookup table, never the raw value"
    ),
    refuses="a getRequestDispatcher path a method body shows request data reaching",
    silent_on="a constant dispatcher path; a path chosen from a fixed lookup table; Spring code",
)
