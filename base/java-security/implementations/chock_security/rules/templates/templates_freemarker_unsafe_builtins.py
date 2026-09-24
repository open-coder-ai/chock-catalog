"""FreeMarker's ?new and ?api builtins reach arbitrary classes and their public API from a template."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "templates-freemarker-unsafe-builtins"

_FACTS = facts("templates")["freemarker_unsafe_builtins"]

_TEMPLATE_MESSAGE = (
    "{token} lets this template reach arbitrary Java classes and call into them directly from "
    "template text -- with an unrestricted class resolver this is remote code execution. Restrict "
    "the class resolver (TemplateClassResolver.SAFER_RESOLVER or ALLOWS_NOTHING_RESOLVER) so "
    "these builtins cannot reach classes the template has no business touching, or remove the "
    f"builtin from the template. A template that must use it needs 'chock: allow {RULE_ID}' on "
    "this line."
)

_JAVA_MESSAGE = (
    "{token} lets any template reach arbitrary Java classes (?new) or their public API (?api), "
    "not just the data the application put in the model -- a template turns into remote code "
    "execution. Configure `TemplateClassResolver.SAFER_RESOLVER` or `ALLOWS_NOTHING_RESOLVER`, "
    "and leave `setAPIBuiltinEnabled` at its default. A service that must allow this needs "
    f"'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """`?new`/`?api` in a template, or the Java calls that widen what they can reach."""
    if text.suffix in {".ftl", ".ftlh", ".ftlx"}:
        for line_no, line in enumerate(text.lines, 1):
            hit = next((t for t in _FACTS["template_tokens"] if t in line), None)
            if hit is not None:
                yield Finding(RULE_ID, text.path, line_no, line, _TEMPLATE_MESSAGE.format(token=hit))
    else:
        for line_no, line in enumerate(text.lines, 1):
            hit = next((t for t in _FACTS["java_tokens"] if t in line), None)
            if hit is not None:
                yield Finding(RULE_ID, text.path, line_no, line, _JAVA_MESSAGE.format(token=hit))


RULE = Rule(
    id=RULE_ID,
    pack="templates",
    title="FreeMarker unrestricted ?new/?api builtin",
    suffixes=(".ftl", ".ftlh", ".ftlx", ".java", ".kt"),
    scan=scan,
    constraint=(
        "never(reach): freemarker ?new(...)|?api in a template, or "
        "setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)|"
        "setAPIBuiltinEnabled(true) in Java "
        "-- restrict the class resolver to SAFER_RESOLVER or ALLOWS_NOTHING_RESOLVER"
    ),
    refuses=(
        "`?new(` and `?api` in a `.ftl`/`.ftlh`/`.ftlx` template, and "
        "`setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)` or "
        "`setAPIBuiltinEnabled(true)` in Java/Kotlin"
    ),
    silent_on="`ALLOWS_NOTHING_RESOLVER` and `SAFER_RESOLVER`",
    cwe=("CWE-470",),
    references=("https://freemarker.apache.org/docs/app_faq.html",),
)
