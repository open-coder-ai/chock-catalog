"""Extra coverage cases for the logging pack, kept separate from logging.py to avoid merge
conflicts with the parallel work adding new rules to this pack.

Rows are (rule id, path, text, line numbers the rule must report); an empty list is a correct
change the rule must stay silent on.
"""

from __future__ import annotations

SENSITIVE_DATA = "logging-sensitive-data"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # logging-sensitive-data: a compound identifier whose LAST segment alone is the secret name
    # (as opposed to the whole name, or the last two segments joined)
    (SENSITIVE_DATA, "C.java", 'log.warn("bad login for {}", user.getPassword());\n', [1]),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = []
