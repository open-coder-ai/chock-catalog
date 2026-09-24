"""A SQL/JPQL/HQL string built by joining in a value lets whoever controls it control the statement."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import methods
from chock_security.pack import Rule, facts

RULE_ID = "persistence-sql-string-concat"

_FACTS = facts("persistence")["sql_concat"]

_MESSAGE = (
    "This query text is built by joining `{what}` into it, so whoever controls that value "
    "controls the statement -- the SQL/JPQL/HQL injection path. Bind it as a parameter instead "
    "(?, :name in JDBC/JPQL, or #{{}} in a MyBatis mapper) rather than joining it into the text. "
    "A dynamic identifier no bind parameter can carry -- a table name, an ORDER BY column -- "
    f"needs 'chock: allow {RULE_ID}' on this line and a validated allowlist behind it."
)

_STRING = r'"[^"]*"'
_IDENT = r"[A-Za-z_]\w*"
#: `"..." + ident` or `ident + "..."` -- the shape a query is joined together in, on one line.
_CONCAT = re.compile(rf'{_STRING}\s*\+\s*({_IDENT})|({_IDENT})\s*\+\s*{_STRING}')
_ASSIGN = re.compile(rf"(?:^|[^=!<>+\-*/%&|^])({_IDENT})\s*=(?!=)")
_APPEND = re.compile(rf"(\w+)\.append\(\s*({_IDENT})\s*\)")
_CONSTANT = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _is_constant(name: str) -> bool:
    """An ALL_CAPS name reads as a fixed constant, never a request-shaped value."""
    return bool(_CONSTANT.match(name))


def _concat_identifier(line: str) -> str | None:
    """The non-constant identifier this line joins onto a string literal with `+`, or None."""
    for match in _CONCAT.finditer(line):
        name = match.group(1) or match.group(2)
        if name and not _is_constant(name):
            return name
    return None


def _formatted_identifier(line: str) -> str | None:
    """`String.format(...)` / `.formatted(...)` with a non-constant, non-literal argument."""
    if "String.format(" not in line and ".formatted(" not in line:
        return None
    for name in re.findall(_IDENT, line):
        if name in {"String", "format", "formatted"} or name.isdigit():
            continue
        if not _is_constant(name):
            return name
    return None


def _built_from(line: str) -> str | None:
    return _concat_identifier(line) or _formatted_identifier(line)


def _is_sql_context(text: FileText) -> bool:
    """Whether this file even speaks JDBC/JPA/Hibernate/jOOQ/MyBatis at all."""
    return text.holds(*_FACTS["context_markers"])


def _sink_hit(line: str) -> str | None:
    return next((sink for sink in _FACTS["sinks"] if sink in line), None)


def scan(text: FileText) -> Iterator[Finding]:
    """A query string a method body shows built by joining, reaching a SQL/JPQL/HQL sink."""
    if text.suffix not in (".java", ".kt") or not _is_sql_context(text):
        return
    for method in methods(text):
        built: dict[str, str] = {}  # variable name -> the value it was built from
        for line_no, line in method.body:
            sink = _sink_hit(line)
            if sink is not None:
                direct = _built_from(line)
                source = direct or next(
                    (value for name, value in built.items() if re.search(rf"\b{re.escape(name)}\b", line)),
                    None,
                )
                if source is not None:
                    yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(what=source))
            for match in _ASSIGN.finditer(line):
                target, rhs = match.group(1), line[match.end() :]
                value = _built_from(rhs)
                if value is not None:
                    built[target] = value
                else:
                    built.pop(target, None)
            for match in _APPEND.finditer(line):
                builder, arg = match.group(1), match.group(2)
                if not _is_constant(arg):
                    built[builder] = arg


RULE = Rule(
    id=RULE_ID,
    pack="persistence",
    title="SQL/JPQL string built by concatenation",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(join): a SQL/JPQL/HQL string built with +|String.format|.formatted|"
        "StringBuilder.append of a non-constant, reaching executeQuery|execute|prepareStatement|"
        "JdbcTemplate.query*|createQuery|createNativeQuery|DSL.sql|@Query "
        "-- bind with ?|:name|#{} instead"
    ),
    refuses=(
        "a query string built by `+`, `String.format`/`.formatted`, or "
        "`StringBuilder`/`StringBuffer.append` of a non-constant value, reaching a JDBC "
        "statement, JdbcTemplate, JPA `EntityManager`, Hibernate session, jOOQ `DSL`, or "
        "`@Query` sink"
    ),
    silent_on=(
        "bind parameters (`?`, `:name`, `#{}`); concatenation of literals or ALL_CAPS "
        "constants only; Criteria API, QueryDSL, and jOOQ DSL builders built from values "
        "rather than joined text; and a file that never mentions JDBC/JPA/Hibernate/jOOQ"
    ),
)
