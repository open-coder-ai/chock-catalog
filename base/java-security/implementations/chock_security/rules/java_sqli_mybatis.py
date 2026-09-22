"""MyBatis ${} pastes the value into the SQL text; #{} binds it as a parameter."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-sqli-mybatis-interpolation"

_FACTS = facts("java")["mybatis"]

_MESSAGE = (
    "MyBatis ${} substitutes this value into the SQL text before the statement is prepared, "
    "so whoever controls the value controls the query. Bind it with #{} instead. A dynamic "
    "identifier that no bind parameter can carry -- a table name, an ORDER BY column -- needs "
    f"'chock: allow {RULE_ID}' on this line and a validated allowlist behind it."
)


def _is_mybatis(text: FileText) -> bool:
    """Whether this file is MyBatis SQL at all. Elsewhere ${} is Gradle, Spring or a JS template."""
    if text.suffix == ".xml":
        return text.holds(*_FACTS["mapper_markers"])
    return text.holds(_FACTS["annotation_import"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every ${} in a MyBatis mapper or a file that imports the MyBatis annotations."""
    if not _is_mybatis(text):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["interpolation"] in line:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="MyBatis string interpolation in SQL",
    suffixes=(".xml", ".java"),
    scan=scan,
    constraint=(
        "never(interpolate): mybatis ${...} in mapper|@Select|@Insert|@Update|@Delete "
        "-- ${} is pasted into the SQL text before preparing; bind with #{...}"
    ),
    refuses="`${}` in a mapper or a MyBatis-annotated source",
    silent_on="`#{}`, and `${}` anywhere that is not MyBatis",
)
