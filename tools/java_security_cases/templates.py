"""Cases for the templates pack: Templates and views.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

UNESCAPED = '<p th:utext="${bio}"></p>\n'
ESCAPED = '<p th:text="${bio}"></p>\n'
XSS = "java-xss-unescaped-template"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    ('java-xss-unescaped-template', 'p.html',
     '<p th:utext="${bio}"></p>\n', [1]),
    ('java-xss-unescaped-template', 'p.html',
     '<p th:text="${bio}"></p>\n', []),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%= user.getName() %>', [1]),
    ('java-xss-unescaped-template', 'p.jsp',
     '<c:out value="${b}" escapeXml="false"/>', [1]),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%-- a comment --%>', []),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%@ page session="false" %>', []),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%! int i; %>', []),
    ('java-xss-unescaped-template', 'p.ftl',
     '${bio?no_esc}\n<#noescape>${x}</#noescape>', [1, 2]),
    ('java-xss-unescaped-template', 'Doc.java',
     '// th:utext is documented here', []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
]
