"""Cases for the build pack: Build and dependencies.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

INSECURE_REPO = "build-insecure-repository"
CHECKSUM = "build-checksum-disabled"
VULN = "build-vulnerable-dependency"
DYNAMIC = "build-dynamic-version"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # --- build-insecure-repository ---------------------------------------------------------
    (INSECURE_REPO, "pom.xml",
     "<project>\n  <repositories>\n    <repository>\n      <id>corp</id>\n"
     "      <url>http://repo.example.com/maven2</url>\n    </repository>\n"
     "  </repositories>\n</project>\n", [5]),
    (INSECURE_REPO, "build.gradle",
     "repositories {\n    maven {\n        url \"http://repo.example.com/maven2\"\n    }\n}\n", [3]),
    (INSECURE_REPO, "build.gradle.kts",
     "repositories {\n    maven {\n        url = uri(\"http://repo.example.com/maven2\")\n        isAllowInsecureProtocol = true\n    }\n}\n",
     [3, 4]),
    (INSECURE_REPO, "gradle-wrapper.properties",
     "distributionBase=GRADLE_USER_HOME\ndistributionUrl=http://services.gradle.org/distributions/gradle-8.5-bin.zip\n",
     [2]),
    (INSECURE_REPO, "pom.xml",
     "<project>\n  <repositories>\n    <repository>\n      <id>corp</id>\n"
     "      <url>https://repo.example.com/maven2</url>\n    </repository>\n"
     "  </repositories>\n</project>\n", []),
    (INSECURE_REPO, "pom.xml",
     "<project>\n  <scm>\n    <url>http://github.example.com/team/repo</url>\n  </scm>\n</project>\n", []),
    (INSECURE_REPO, "build.gradle",
     "repositories {\n    maven {\n        url \"http://localhost:8081/repository/internal\"\n    }\n}\n", []),
    (INSECURE_REPO, "build.gradle",
     "repositories {\n    mavenCentral()\n    google()\n}\n", []),

    # --- build-checksum-disabled -------------------------------------------------------------
    (CHECKSUM, "pom.xml",
     "<project>\n  <repositories>\n    <repository>\n      <releases>\n"
     "        <checksumPolicy>ignore</checksumPolicy>\n      </releases>\n"
     "    </repository>\n  </repositories>\n</project>\n", [5]),
    (CHECKSUM, "gradle.properties",
     "org.gradle.caching=true\norg.gradle.dependency.verification=off\n", [2]),
    (CHECKSUM, "pom.xml",
     "<project>\n  <repositories>\n    <repository>\n      <releases>\n"
     "        <checksumPolicy>fail</checksumPolicy>\n      </releases>\n"
     "    </repository>\n  </repositories>\n</project>\n", []),
    (CHECKSUM, "gradle.properties",
     "org.gradle.caching=true\norg.gradle.dependency.verification=strict\n", []),
    (CHECKSUM, "application.properties",
     "org.gradle.dependency.verification=off\n", []),

    # --- build-vulnerable-dependency -----------------------------------------------------------
    (VULN, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>org.apache.logging.log4j</groupId>\n"
     "      <artifactId>log4j-core</artifactId>\n      <version>2.14.1</version>\n"
     "    </dependency>\n  </dependencies>\n</project>\n", [6]),
    (VULN, "pom.xml",
     "<project>\n  <properties>\n    <log4j.version>2.14.1</log4j.version>\n  </properties>\n"
     "  <dependencies>\n    <dependency>\n"
     "      <groupId>org.apache.logging.log4j</groupId>\n"
     "      <artifactId>log4j-core</artifactId>\n      <version>${log4j.version}</version>\n"
     "    </dependency>\n  </dependencies>\n</project>\n", [9]),
    (VULN, "build.gradle",
     "dependencies {\n    implementation \"org.apache.logging.log4j:log4j-core:2.14.1\"\n}\n", [2]),
    (VULN, "build.gradle.kts",
     "dependencies {\n    implementation(\"com.h2database:h2:2.0.206\")\n}\n", [2]),
    (VULN, "build.gradle",
     "dependencies {\n    implementation group: 'org.yaml', name: 'snakeyaml', version: '1.30'\n}\n", [2]),
    (VULN, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>org.apache.logging.log4j</groupId>\n"
     "      <artifactId>log4j-core</artifactId>\n      <version>2.17.1</version>\n"
     "    </dependency>\n  </dependencies>\n</project>\n", []),
    (VULN, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>org.apache.logging.log4j</groupId>\n"
     "      <artifactId>log4j-core</artifactId>\n      <version>2.12.4</version>\n"
     "    </dependency>\n  </dependencies>\n</project>\n", []),
    (VULN, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>org.apache.logging.log4j</groupId>\n"
     "      <artifactId>log4j-core</artifactId>\n"
     "    </dependency>\n  </dependencies>\n</project>\n", []),
    (VULN, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>org.apache.logging.log4j</groupId>\n"
     "      <artifactId>log4j-core</artifactId>\n      <version>${log4j.version}</version>\n"
     "    </dependency>\n  </dependencies>\n</project>\n", []),
    (VULN, "build.gradle",
     "dependencies {\n    implementation \"com.google.guava:guava:32.1.3-jre\"\n}\n", []),

    # --- build-dynamic-version -----------------------------------------------------------------
    (DYNAMIC, "build.gradle",
     "dependencies {\n    implementation \"com.squareup.okhttp3:okhttp:4.+\"\n}\n", [2]),
    (DYNAMIC, "build.gradle.kts",
     "dependencies {\n    implementation(\"com.squareup.okhttp3:okhttp:latest.release\")\n}\n", [2]),
    (DYNAMIC, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n"
     "      <version>LATEST</version>\n    </dependency>\n  </dependencies>\n</project>\n", [6]),
    (DYNAMIC, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n"
     "      <version>[1.0,)</version>\n    </dependency>\n  </dependencies>\n</project>\n", [6]),
    (DYNAMIC, "build.gradle",
     "dependencies {\n    implementation \"com.squareup.okhttp3:okhttp:4.12.0\"\n}\n", []),
    (DYNAMIC, "pom.xml",
     "<project>\n  <dependencies>\n    <dependency>\n"
     "      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n"
     "      <version>[1.0,2.0]</version>\n    </dependency>\n  </dependencies>\n</project>\n", []),
    ('build-vulnerable-dependency', 'pom.xml',
     '<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n      <artifactId>log4j-core</artifactId>\n      <version>2.12.3</version>\n    </dependency>\n  </dependencies>\n</project>\n', [6]),
    ('build-vulnerable-dependency', 'pom.xml',
     '<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n      <artifactId>log4j-core</artifactId>\n      <version>2.12.4</version>\n    </dependency>\n  </dependencies>\n</project>\n', []),
    ('build-vulnerable-dependency', 'pom.xml',
     '<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.thoughtworks.xstream</groupId>\n      <artifactId>xstream</artifactId>\n      <version>1.4.17</version>\n    </dependency>\n  </dependencies>\n</project>\n', [6]),
    ('build-vulnerable-dependency', 'pom.xml',
     '<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.thoughtworks.xstream</groupId>\n      <artifactId>xstream</artifactId>\n      <version>1.4.18</version>\n    </dependency>\n  </dependencies>\n</project>\n', []),
    ('build-vulnerable-dependency', 'pom.xml',
     '<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.fasterxml.jackson.core</groupId>\n      <artifactId>jackson-databind</artifactId>\n      <version>2.13.0</version>\n    </dependency>\n  </dependencies>\n</project>\n', []),
    ('build-insecure-repository', 'pom.xml',
     '<project>\n  <repositories>\n    <repository><id>c</id><url>https://repo.example.com/m2</url></repository>\n  </repositories>\n  <scm><url>http://github.com/acme/app</url></scm>\n  <mirrors><mirror><url>http://mirror.example.com/m2</url></mirror></mirrors>\n</project>\n', [6]),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
]
