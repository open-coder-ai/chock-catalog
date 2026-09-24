"""Cases for the spring pack: Spring.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

CREDENTIALS = "config.setAllowCredentials(true);\n"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    ('java-cors-wildcard-credentials', 'Cors.java',
     'config.setAllowCredentials(true);\nconfig.setAllowedOrigins(List.of("*"));\n', [2]),
    ('java-cors-wildcard-credentials', 'Api.java',
     '@CrossOrigin(origins = "*", allowCredentials = "true")\n', [1]),
    ('java-cors-wildcard-credentials', 'Cors.java',
     'config.setAllowedOrigins(List.of("*"));\n', []),
    ('java-cors-wildcard-credentials', 'Cors.java',
     'config.setAllowCredentials(true);\nconfig.setAllowedOrigins(List.of("https://app.example.com"));\n', []),
    ('java-cors-wildcard-credentials', 'Cors.java',
     'config.setAllowCredentials(true);\nconfig.setAllowedOriginPatterns(List.of("*"));\n', []),
    ('java-cors-wildcard-credentials', 'Cors.java',
     'config.setAllowCredentials(true);\nconfig.addAllowedOriginPattern("*");\n', []),
    ('java-actuator-wildcard-exposure', 'application.properties',
     'management.endpoints.web.exposure.include=*\n', [1]),
    ('java-actuator-wildcard-exposure', 'application.yml',
     'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n', [5]),
    ('java-actuator-wildcard-exposure', 'application.properties',
     'management.endpoints.web.exposure.include=health,info,metrics\n', []),
    ('java-actuator-wildcard-exposure', 'codecov.yml',
     'coverage:\n  include: "*"\n', []),
    ('java-actuator-wildcard-exposure', 'codecov.yml',
     '# operational exposure notes: keep actuator endpoints minimal\ncoverage:\n  include: "*.yml"\n', []),
    ('java-actuator-wildcard-exposure', 'application.yml',
     'management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info\n  other:\n    include: "*"\n', []),
    ('java-actuator-wildcard-exposure', 'application.properties',
     'server.port=8080\n', []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
]
