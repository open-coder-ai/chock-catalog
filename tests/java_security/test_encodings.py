"""Every rule decides the same on the text a Windows machine writes as on the text a Unix one does.

Git for Windows checks files out with CRLF line endings by default, and Windows editors and tools
often write a UTF-8 byte-order mark. Neither is content. Every rule case and flow case is replayed
with CRLF endings and with a BOM, and must report exactly the lines it reports on the plain text.
"""

from __future__ import annotations

import pytest
from chock_security.decision import DENY, FileText
from chock_security.engine import evaluate
from chock_security.rules import registry
from java_security.cases import CASES, FLOW_CASES

ALL_DENY = dict.fromkeys(registry(), DENY)
VARIANTS = {
    "crlf": lambda text: text.replace("\n", "\r\n"),
    "bom": lambda text: "﻿" + text,
    "bom+crlf": lambda text: "﻿" + text.replace("\n", "\r\n"),
}
TEXTS = [(path, text) for _, path, text, _ in CASES] + [(path, text) for _, path, text, _, _ in FLOW_CASES]


def _reported(path: str, text: str) -> list[tuple[str, int]]:
    return sorted((f.rule_id, f.line_no) for f in evaluate([FileText(path, text)], ALL_DENY))


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_every_case_is_judged_the_same_whatever_the_line_endings_or_bom(variant: str) -> None:
    change = VARIANTS[variant]
    differ = [path for path, text in TEXTS if _reported(path, change(text)) != _reported(path, text)]
    assert differ == [], f"{len(differ)} case(s) judged differently under {variant}"


def test_the_bom_is_not_part_of_the_text_a_rule_reads() -> None:
    assert FileText("application.properties", "﻿a=b\n").lines == ["a=b"]
