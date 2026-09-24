"""Cases for the exceptions pack: Exception handling.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = []
