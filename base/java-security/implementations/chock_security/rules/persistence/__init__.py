"""The persistence pack: Persistence."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.persistence import java_sqli_mybatis

PACK = Pack(
    id="persistence",
    title="Persistence",
    covers=(
        "JDBC, JPA and Hibernate, JdbcTemplate, MyBatis, jOOQ, MongoDB and other NoSQL drivers, and the JDBC URLs and schema settings that configure them."
    ),
)

RULES: tuple[Rule, ...] = (
    java_sqli_mybatis.RULE,
)
