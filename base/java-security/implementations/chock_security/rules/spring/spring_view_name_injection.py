"""A view name built from request data lets the caller choose a Thymeleaf fragment expression --
`return "user/" + lang;` resolves to a template path the engine then evaluates as one."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import methods, reaching
from chock_security.pack import Rule, facts

RULE_ID = "spring-view-name-injection"

_FACTS = facts("spring")["view_name"]

_MESSAGE = (
    "This view name is built from {source}, and Thymeleaf resolves a fragment expression inside "
    "the resolved template path -- the caller ends up choosing more than which file loads. Map the "
    "request value to a view name through a fixed lookup (an enum or an allowlisted set of "
    "constants), never by concatenating it into the returned string."
)


def _guarded_class(text: FileText) -> bool:
    """A @Controller class returning view names -- not @RestController, which returns bodies."""
    return text.holds("@Controller") and not text.holds("@RestController")


def _response_body_above(text: FileText, body_start: int) -> bool:
    """@ResponseBody on this method turns its return value into a body, not a view name."""
    window = _FACTS["response_body_window"]
    start = max(0, body_start - 1 - window)
    return "@ResponseBody" in "\n".join(text.lines[start : body_start - 1])


def scan(text: FileText) -> Iterator[Finding]:
    """Every `return "<constant>" + <request data>` in a @Controller method that is not @ResponseBody."""
    if not _guarded_class(text):
        return
    for method in methods(text):
        if not method.body:
            continue
        if _response_body_above(text, method.body[0][0]):
            continue
        for flow in reaching(method, [_FACTS["sink"]]):
            if "redirect:" in flow.line or "forward:" in flow.line:
                continue  # a redirect/forward prefix is not a view name; the redirect rule owns it
            yield Finding(RULE_ID, text.path, flow.line_no, flow.line, _MESSAGE.format(source=flow.source))


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="View name built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        'never(return): a view name concatenated with request data in a @Controller method '
        "-- map the value to a view name through a fixed lookup instead"
    ),
    refuses='return "prefix/" + <request data>; in a @Controller method that is not @ResponseBody',
    silent_on="a constant view name; @RestController classes; a method annotated @ResponseBody; "
    'a "redirect:"/"forward:" prefix (the open-redirect rule owns those)',
)
