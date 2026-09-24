"""Extra coverage cases for the persistence pack, kept separate from persistence.py so that file
stays under the line limit.

Rows are (rule id, path, text, line numbers the rule must report); an empty list is a correct
change the rule must stay silent on.
"""

from __future__ import annotations

CONCAT = "persistence-sql-string-concat"
JDBC_URL = "persistence-jdbc-url-unsafe"
DDL = "persistence-destructive-ddl"
NOSQL = "persistence-nosql-injection"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # persistence-sql-string-concat: a StringBuilder tracked across lines, appended a
    # non-constant value, then used at the sink on a later line
    (
        CONCAT,
        "R.java",
        "import java.sql.Statement;\n"
        "public class R {\n"
        "  public void run(Statement st, String id) throws Exception {\n"
        '    StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE id = ");\n'
        "    sb.append(id);\n"
        "    st.executeQuery(sb.toString());\n"
        "  }\n}\n",
        [6],
    ),
    # persistence-sql-string-concat: String.format() with a genuine non-constant argument, no
    # "+" concatenation on the line at all
    (
        CONCAT,
        "R.java",
        "import java.sql.Statement;\n"
        "public class R {\n"
        "  public void run(Statement st, String status) throws Exception {\n"
        "    st.executeQuery(String.format(\"SELECT * FROM t WHERE status = '%s'\", status));\n"
        "  }\n}\n",
        [4],
    ),
    # persistence-sql-string-concat: String.format() with only constant/literal arguments must
    # stay silent -- this used to false-positive by matching a word inside the template string
    (
        CONCAT,
        "R.java",
        "import java.sql.Statement;\n"
        "public class R {\n"
        "  public void run(Statement st) throws Exception {\n"
        '    String sql = String.format("SELECT * FROM t WHERE status = \'%s\'", "ACTIVE");\n'
        "    st.executeQuery(sql);\n"
        "  }\n}\n",
        [],
    ),
    # persistence-sql-string-concat: String.format() with a leading ALL_CAPS constant argument,
    # then a real non-constant one
    (
        CONCAT,
        "R.java",
        "import java.sql.Statement;\n"
        "public class R {\n"
        "  public void run(Statement st, String status) throws Exception {\n"
        '    st.executeQuery(String.format("SELECT * FROM t WHERE code = %s AND status = %s", CODE, status));\n'
        "  }\n}\n",
        [4],
    ),
    # persistence-sql-string-concat: .append() of an ALL_CAPS constant is never tracked as a
    # source, so a builder fed only constants must stay silent
    (
        CONCAT,
        "R.java",
        "import java.sql.Statement;\n"
        "public class R {\n"
        "  public void run(Statement st) throws Exception {\n"
        '    StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE code = ");\n'
        "    sb.append(STATUS_CODE);\n"
        "    st.executeQuery(sb.toString());\n"
        "  }\n}\n",
        [],
    ),
    # persistence-jdbc-url-unsafe: two separate jdbc: URLs in the same file, each flagged on its
    # own line, the second reusing the "local" determination the first already made
    (
        JDBC_URL,
        "application.properties",
        "db.primary.url=jdbc:mysql://prod-db:3306/app?useSSL=false\n"
        "db.replica.url=jdbc:mysql://prod-replica:3306/app?trustServerCertificate=true\n",
        [1, 2],
    ),
    # persistence-destructive-ddl: a comment and a blank line before the flattened key
    (
        DDL,
        "application.properties",
        "# hibernate config\n\nspring.jpa.hibernate.ddl-auto=create\n",
        [3],
    ),
    # persistence-destructive-ddl: a comment, a blank line, and a folded YAML scalar with no
    # colon of its own, all before the real key at its nested nesting
    (
        DDL,
        "application.yml",
        "spring:\n"
        "  # jpa settings\n"
        "\n"
        "  jpa:\n"
        "    description: >\n"
        "      multiline\n"
        "      value\n"
        "    hibernate:\n"
        "      ddl-auto: create\n",
        [9],
    ),
    # persistence-destructive-ddl: an XML file with a non-matching <property> before the
    # destructive one, so the scan must continue past it
    (
        DDL,
        "persistence.xml",
        "<persistence>\n"
        "  <properties>\n"
        '    <property name="hibernate.dialect" value="org.hibernate.dialect.PostgreSQLDialect"/>\n'
        '    <property name="javax.persistence.schema-generation.database.action" value="drop"/>\n'
        "  </properties>\n</persistence>\n",
        [4],
    ),
    # persistence-nosql-injection: a $where clause joining an ALL_CAPS constant first, then a
    # real, non-constant identifier
    (
        NOSQL,
        "M.java",
        "import com.mongodb.client.MongoCollection;\n"
        "public class M {\n"
        "  public void run(MongoCollection<?> c, String name) {\n"
        '    c.find(new BasicDBObject("$where", "this.status == \'" + STATUS + "\' && this.name == \'" + name + "\'"));\n'
        "  }\n}\n",
        [4],
    ),
    # persistence-nosql-injection: a $where clause with no concatenation at all -- a fixed
    # literal condition
    (
        NOSQL,
        "M.java",
        "import com.mongodb.client.MongoCollection;\n"
        "public class M {\n"
        "  public void run(MongoCollection<?> c) {\n"
        '    c.find(new BasicDBObject("$where", "this.active == true"));\n'
        "  }\n}\n",
        [],
    ),
    # persistence-nosql-injection: a parse sink whose line matches both the direct-concat check
    # and a request-data flow -- the flow pass must not report it a second time
    (
        NOSQL,
        "M.java",
        "import org.bson.Document;\n"
        "public class M {\n"
        "  public void run(@RequestParam String name) {\n"
        "    Document d = Document.parse(\"{ 'name': '\" + name + \"' }\");\n"
        "  }\n}\n",
        [4],
    ),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = []
