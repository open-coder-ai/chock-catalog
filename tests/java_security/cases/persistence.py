"""Cases for the persistence pack: Persistence.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

from java_security.cases.persistence_edges import CASES as EDGE_CASES

MAPPER = '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN">\n<mapper namespace="a">\n'

CONCAT = "persistence-sql-string-concat"
JDBC_URL = "persistence-jdbc-url-unsafe"
DDL = "persistence-destructive-ddl"
NOSQL = "persistence-nosql-injection"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    (
        "java-sqli-mybatis-interpolation",
        "UserMapper.xml",
        '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN">\n<mapper namespace="a">\nSELECT * FROM t ORDER BY ${col}',
        [3],
    ),
    (
        "java-sqli-mybatis-interpolation",
        "UserMapper.java",
        'import org.apache.ibatis.annotations.Select;\n@Select("SELECT * FROM ${t}")\n',
        [2],
    ),
    (
        "java-sqli-mybatis-interpolation",
        "UserMapper.xml",
        '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN">\n<mapper namespace="a">\nSELECT * FROM t WHERE id = #{id}',
        [],
    ),
    (
        "java-sqli-mybatis-interpolation",
        "pom.xml",
        "<project>\n  <version>${project.version}</version>\n</project>\n",
        [],
    ),
    (
        "java-sqli-mybatis-interpolation",
        "Config.java",
        'import org.springframework.beans.factory.annotation.Value;\n@Value("${app.url}")\n',
        [],
    ),
    # persistence-sql-string-concat
    (
        CONCAT,
        "R.java",
        "import org.springframework.jdbc.core.JdbcTemplate;\n"
        "public class R {\n"
        "  public void run(JdbcTemplate jdbc, String name) {\n"
        '    jdbc.query("SELECT * FROM users WHERE name = \'" + name + "\'", mapper);\n'
        "  }\n}\n",
        [4],
    ),
    (
        CONCAT,
        "R.java",
        "import java.sql.Statement;\n"
        "public class R {\n"
        "  public void run(Statement st, String name) throws Exception {\n"
        '    String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";\n'
        "    st.executeQuery(sql);\n"
        "  }\n}\n",
        [5],
    ),
    (
        CONCAT,
        "R.java",
        "import java.sql.Connection;\n"
        "public class R {\n"
        "  public void run(Connection conn) throws Exception {\n"
        '    conn.prepareStatement("SELECT * FROM users WHERE name = ?");\n'
        "  }\n}\n",
        [],
    ),
    (
        CONCAT,
        "R.java",
        "import java.sql.Statement;\n"
        "public class R {\n"
        '  static final String TABLE = "users";\n'
        "  public void run(Statement st) throws Exception {\n"
        '    st.executeQuery("SELECT * FROM " + TABLE);\n'
        "  }\n}\n",
        [],
    ),
    (
        CONCAT,
        "R.java",
        "public class R {\n"
        "  public void run(String cmd) {\n"
        '    String full = "echo " + cmd;\n'
        "    runner.execute(full);\n"
        "  }\n}\n",
        [],
    ),
    (
        CONCAT,
        "R.java",
        "import javax.persistence.criteria.CriteriaBuilder;\n"
        "public class R {\n"
        "  public void run(CriteriaBuilder cb, String name) {\n"
        '    cb.equal(cb.parameter(String.class, "name"), name);\n'
        "  }\n}\n",
        [],
    ),
    (
        CONCAT,
        "R.java",
        "import org.jooq.DSLContext;\n"
        "public class R {\n"
        "  public void run(DSLContext dsl, String name) {\n"
        "    dsl.selectFrom(USERS).where(USERS.NAME.eq(name)).fetch();\n"
        "  }\n}\n",
        [],
    ),
    # persistence-jdbc-url-unsafe
    (JDBC_URL, "Db.java", 'String url = "jdbc:mysql://db.example.com:3306/app?autoDeserialize=true";\n', [1]),
    (
        JDBC_URL,
        "application.properties",
        "spring.datasource.url=jdbc:postgresql://db.example.com:5432/app?sslmode=disable\n",
        [1],
    ),
    (JDBC_URL, "Db.java", 'String url = "jdbc:mysql://localhost:3306/app?allowLoadLocalInfile=true";\n', [1]),
    (JDBC_URL, "application.properties", "spring.datasource.url=jdbc:mysql://localhost:3306/app?useSSL=false\n", []),
    (
        JDBC_URL,
        "application.properties",
        "spring.datasource.url=jdbc:postgresql://db.example.com:5432/app?ssl=true\n",
        [],
    ),
    (JDBC_URL, "src/test/java/Db.java", 'String url = "jdbc:mysql://localhost:3306/app?autoDeserialize=true";\n', []),
    # persistence-destructive-ddl
    (DDL, "application.properties", "spring.jpa.hibernate.ddl-auto=create\n", [1]),
    (DDL, "application.yml", "spring:\n  jpa:\n    hibernate:\n      ddl-auto: update\n", [4]),
    (
        DDL,
        "persistence.xml",
        '<property name="javax.persistence.schema-generation.database.action" value="drop"/>\n',
        [1],
    ),
    (DDL, "application.properties", "spring.jpa.hibernate.ddl-auto=validate\n", []),
    (DDL, "application-dev.properties", "spring.jpa.hibernate.ddl-auto=create\n", []),
    (DDL, "src/test/resources/application.properties", "spring.jpa.hibernate.ddl-auto=create\n", []),
    (DDL, "application.yml", "server:\n  port: 8080\n", []),
    # persistence-nosql-injection
    (
        NOSQL,
        "M.java",
        "import com.mongodb.client.MongoCollection;\n"
        "public class M {\n"
        "  public void run(MongoCollection<?> c, String name) {\n"
        '    c.find(new BasicDBObject("$where", "this.name == \'" + name + "\'"));\n'
        "  }\n}\n",
        [4],
    ),
    (
        NOSQL,
        "M.java",
        "import org.bson.Document;\n"
        "public class M {\n"
        "  public void run(String filterJson) {\n"
        "    Document d = Document.parse(\"{ 'name': '\" + filterJson + \"' }\");\n"
        "  }\n}\n",
        [4],
    ),
    (
        NOSQL,
        "M.java",
        "import org.springframework.data.mongodb.core.query.BasicQuery;\n"
        "public class M {\n"
        "  public void run(@RequestParam String filter) {\n"
        "    BasicQuery q = new BasicQuery(filter);\n"
        "  }\n}\n",
        [4],
    ),
    (
        NOSQL,
        "M.java",
        "import org.bson.Document;\n"
        "public class M {\n"
        "  public void run() {\n"
        "    Document d = Document.parse(\"{ 'active': true }\");\n"
        "  }\n}\n",
        [],
    ),
    (
        NOSQL,
        "M.java",
        "import com.mongodb.client.MongoCollection;\n"
        "public class M {\n"
        "  public void run(MongoCollection<?> c) {\n"
        '    c.find(new BasicDBObject("name", "static"));\n'
        "  }\n}\n",
        [],
    ),
    (
        NOSQL,
        "M.java",
        "public class M {\n"
        "  public void run(String filterJson) {\n"
        "    Document d = Document.parse(\"{ 'name': '\" + filterJson + \"' }\");\n"
        "  }\n}\n",
        [],
    ),
    (
        "persistence-sql-string-concat",
        "D.java",
        'import java.sql.*;\npublic class D {\n  ResultSet a(Statement st, String id) throws Exception { return st.executeQuery("SELECT * FROM t WHERE id = " + id); }\n  int b(long id) { return jdbc.update("DELETE FROM t WHERE id = ?", id); }\n}\n',
        [3],
    ),
    *EDGE_CASES,
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = []
