"""The review's 46 comment cases: a dangerous API named only where no code runs, which must be allowed.

Thirteen constructs, each written as a `//` comment, as Javadoc `{@code ...}` and inside a string
literal that is only advice text, in an otherwise empty class; then seven config and build cases. Source:
witness/reviews/2026-11-15-policy-hardening/REVIEW-java-security.md, section 3.2 and the appendix.
CASES rows are (case id, path, text); the gate must allow every one.
"""

from __future__ import annotations

JAVA = "src/main/java/com/acme/app/Notes.java"
SPRING_HTTP = "import org.springframework.security.config.annotation.web.builders.HttpSecurity;"

#: (name, imports, the code the comment or literal talks about)
CONSTRUCTS = [
    ("weak-cipher", ["import javax.crypto.Cipher;"], 'Cipher.getInstance("AES/ECB/PKCS5Padding")'),
    (
        "md5-password",
        ["import java.security.MessageDigest;"],
        'MessageDigest.getInstance("MD5").digest(password.getBytes())',
    ),
    ("csrf-disable", [SPRING_HTTP], "http.csrf().disable()"),
    ("permit-all", [SPRING_HTTP], "http.authorizeHttpRequests(a -> a.anyRequest().permitAll())"),
    (
        "ois",
        ["import java.io.ObjectInputStream;", "import javax.servlet.http.HttpServletRequest;"],
        "new ObjectInputStream(request.getInputStream()).readObject()",
    ),
    ("default-typing", ["import com.fasterxml.jackson.databind.ObjectMapper;"], "mapper.enableDefaultTyping()"),
    ("xstream", ["import com.thoughtworks.xstream.XStream;"], "new XStream().fromXML(xml)"),
    (
        "xxe",
        ["import javax.xml.parsers.DocumentBuilderFactory;"],
        "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in)",
    ),
    (
        "sql-concat",
        ["import java.sql.Statement;"],
        "stmt.executeQuery(\"SELECT * FROM t WHERE a = '\" + name + \"'\")",
    ),
    (
        "hostname-verifier",
        ["import javax.net.ssl.HttpsURLConnection;"],
        "HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true)",
    ),
    (
        "cors",
        ["import org.springframework.web.cors.CorsConfiguration;"],
        'config.addAllowedOrigin("*"); config.setAllowCredentials(true)',
    ),
    ("math-random-token", [], "String token = Long.toHexString((long) (Math.random() * Long.MAX_VALUE))"),
    (
        "noop-verifier",
        ["import org.apache.http.conn.ssl.NoopHostnameVerifier;"],
        "builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)",
    ),
]

_METHOD = '    public String describe() {{\n{body}        return {value};\n    }}\n'


def _class(imports: list[str], before: str, members: str, body: str, value: str) -> str:
    head = "package com.acme.app;\n\n" + "\n".join(imports) + "\n\n"
    return head + before + "public class Notes {\n" + members + _METHOD.format(body=body, value=value) + "}\n"


def _line(imports: list[str], code: str) -> str:
    return _class(imports, "", "", f"        // legacy code did: {code}\n", '"ok"')


def _javadoc(imports: list[str], code: str) -> str:
    doc = f"/**\n * Do not write {{@code {code}}} in this module.\n */\n"
    return _class(imports, doc, "", "", '"ok"')


def _literal(imports: list[str], code: str) -> str:
    advice = code.replace('"', '\\"')
    members = f'    private static final String ADVICE = "Avoid: {advice}";\n\n'
    return _class(imports, "", members, "", "ADVICE")


_FORMS = (("line", _line), ("doc", _javadoc), ("str", _literal))

_MAPPER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">\n'
    '<mapper namespace="a.A">\n'
    "  <!-- old form, removed: ORDER BY ${col} -->\n"
    '  <select id="list" resultType="a.Row">SELECT id FROM t WHERE k = #{k}</select>\n'
    "</mapper>\n"
)

_POM = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
    "  <modelVersion>4.0.0</modelVersion>\n"
    "  <groupId>com.acme</groupId>\n"
    "  <artifactId>orders</artifactId>\n"
    "  <version>1.4.0</version>\n"
    "  <dependencies>\n"
    "    <!-- before the Log4Shell upgrade:\n"
    "    <dependency>\n"
    "      <groupId>org.apache.logging.log4j</groupId>\n"
    "      <artifactId>log4j-core</artifactId>\n"
    "      <version>2.14.1</version>\n"
    "    </dependency>\n"
    "    -->\n"
    "    <dependency>\n"
    "      <groupId>org.apache.logging.log4j</groupId>\n"
    "      <artifactId>log4j-core</artifactId>\n"
    "      <version>2.17.2</version>\n"
    "    </dependency>\n"
    "  </dependencies>\n"
    "</project>\n"
)

_CONFIG = [
    ("cm-mybatis-xml", "src/main/resources/mapper/A.xml", _MAPPER),
    (
        "cm-props-secret",
        "src/main/resources/application.properties",
        "# spring.datasource.password=hunter2  (moved to the vault, 2024)\n"
        "spring.datasource.password=${DATABASE_PASSWORD}\n",
    ),
    (
        "cm-props-actuator",
        "src/main/resources/application.properties",
        "# do not set management.endpoints.web.exposure.include=* in production\n"
        "management.endpoints.web.exposure.include=health,info\n",
    ),
    (
        "cm-yaml-actuator",
        "src/main/resources/application.yml",
        "management:\n  endpoints:\n    web:\n      exposure:\n"
        '        # include: "*"   <- never in prod\n'
        "        include: health,info\n",
    ),
    ("cm-pom-dep", "pom.xml", _POM),
    (
        "cm-gradle-dep",
        "build.gradle",
        "dependencies {\n"
        "    // implementation 'org.apache.logging.log4j:log4j-core:2.14.1'  // upgraded for CVE-2021-44228\n"
        "    implementation 'org.apache.logging.log4j:log4j-core:2.17.2'\n"
        "}\n",
    ),
    (
        "cm-changelog-md",
        "CHANGELOG.md",
        "## 1.4.0\n"
        "- Upgraded `org.apache.logging.log4j:log4j-core:2.14.1` to 2.17.2.\n"
        "- Removed `http.csrf().disable()` from the web chain.\n",
    ),
]

CASES: list[tuple[str, str, str]] = [
    (f"cm-{name}-{form}", JAVA, build(imports, code)) for name, imports, code in CONSTRUCTS for form, build in _FORMS
] + _CONFIG
