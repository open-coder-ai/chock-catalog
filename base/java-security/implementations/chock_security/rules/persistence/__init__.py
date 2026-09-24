"""The persistence pack: Persistence."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.persistence import (
    java_sqli_mybatis,
    persistence_destructive_ddl,
    persistence_jdbc_url_unsafe,
    persistence_nosql_injection,
    persistence_sql_string_concat,
)

PACK = Pack(
    id="persistence",
    title="Persistence",
    covers=(
        "JDBC, JPA and Hibernate, JdbcTemplate, MyBatis, jOOQ, MongoDB and other NoSQL drivers, and the JDBC URLs and schema settings that configure them."
    ),
)

RULES: tuple[Rule, ...] = (
    java_sqli_mybatis.RULE,
    persistence_sql_string_concat.RULE,
    persistence_jdbc_url_unsafe.RULE,
    persistence_destructive_ddl.RULE,
    persistence_nosql_injection.RULE,
)
