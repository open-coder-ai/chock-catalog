"""Extra coverage cases for the jakarta pack, kept separate from jakarta.py/jakarta_config.py to
avoid merge conflicts with the parallel work adding new rules to this pack.

Rows are (rule id, path, text, line numbers the rule must report); an empty list is a correct
change the rule must stay silent on.
"""

from __future__ import annotations

SECURITY_DISABLED = "jakarta-security-disabled"
CORS = "jakarta-cors-wildcard-credentials"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # jakarta-security-disabled: a comment/blank line before the flattened key, in .properties
    (
        SECURITY_DISABLED,
        "application.properties",
        "# Micronaut config\n\nmicronaut.security.enabled=false\n",
        [3],
    ),
    # jakarta-security-disabled: nested YAML the key never appears in -- unrelated siblings at
    # several depths, a folded multi-line scalar with no colon of its own, and a dedent back to
    # the top level -- all of it must stay silent since micronaut.security.enabled is never set.
    (
        SECURITY_DISABLED,
        "application.yml",
        "micronaut:\n"
        "  http:\n"
        "    services:\n"
        "      catalog:\n"
        "        description: >\n"
        "          A multi-line\n"
        "          folded description\n"
        "        url: https://example.com\n"
        "server:\n"
        "  port: 8080\n",
        [],
    ),
    # jakarta-cors-wildcard-credentials: a micronaut allowed-origins wildcard written on one line
    (
        CORS,
        "application.yml",
        "micronaut:\n"
        "  server:\n"
        "    cors:\n"
        "      configurations:\n"
        "        web:\n"
        "          allow-credentials: true\n"
        '          allowed-origins: "*"\n',
        [7],
    ),
    # jakarta-cors-wildcard-credentials: a named-origins sequence with a blank line before its
    # first item, followed by a sibling key at the same indent -- no wildcard, so this stays
    # silent, and the sibling ends the sequence scan before it ever reaches end of file.
    (
        CORS,
        "application.yml",
        "micronaut:\n"
        "  server:\n"
        "    cors:\n"
        "      configurations:\n"
        "        web:\n"
        "          allow-credentials: true\n"
        "          allowed-origins:\n"
        "\n"
        '            - "https://app.example.com"\n'
        "          allow-headers:\n"
        '            - "*"\n',
        [],
    ),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = []
