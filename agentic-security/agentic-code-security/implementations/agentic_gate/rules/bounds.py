"""The bounds pack (ASI08): loop limits removed or set so high they no longer stop a runaway agent."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agentic_gate import jsscan
from agentic_gate.model import ALLOW, FileText, Hit, Pack, Rule
from agentic_gate.pyast import is_const, settings
from agentic_gate.textscan import line_of

PACK = Pack(
    id="bounds",
    title="Cascading failure bounds",
    covers="Turn, reply, recursion and iteration limits on agent loops.",
    asi=("ASI08",),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_UNBOUNDED_KEYS = ("max_turns", "max_consecutive_auto_reply")
_RECURSION_CEILING = 1000
_ITERATION_CEILING = 100
_JS_RECURSION = re.compile(r"\brecursionLimit\s*:\s*(\d+)")


def _at_least(value: ast.expr, ceiling: int) -> bool:
    return isinstance(value, ast.Constant) and type(value.value) is int and value.value >= ceiling


def _unbounded(text: FileText) -> Iterator[Hit]:
    for key in _UNBOUNDED_KEYS:
        for line_no, value in settings(text, key):
            if is_const(value, None):
                yield Hit(line_no, f"{key}=None removes the only cap on how long the agent loop can run.")


def _recursion(text: FileText) -> Iterator[Hit]:
    detail = f"a recursion_limit of {_RECURSION_CEILING} or more lets a looping graph run for thousands of steps."
    for line_no, value in settings(text, "recursion_limit"):
        if _at_least(value, _RECURSION_CEILING):
            yield Hit(line_no, detail)
    if text.kind == "js":
        view = jsscan.shape(text.text)
        for found in _JS_RECURSION.finditer(view):
            if int(found.group(1)) >= _RECURSION_CEILING:
                yield Hit(line_of(view, found.start()), detail)


def _max_iter(text: FileText) -> Iterator[Hit]:
    for line_no, value in settings(text, "max_iter"):
        if _at_least(value, _ITERATION_CEILING):
            yield Hit(
                line_no, f"max_iter of {_ITERATION_CEILING} or more lets one task loop through hundreds of model calls."
            )


RULES: tuple[Rule, ...] = (
    Rule(
        id="bounds-unbounded-turns",
        pack="bounds",
        title="Agent loop with no turn or reply limit",
        why="With no cap a confused or manipulated agent loops on paid model calls and tools until something else stops it.",
        kinds=("python",),
        scan=_unbounded,
        fix="set a finite max_turns or max_consecutive_auto_reply sized to the task, and a wall-clock timeout.",
        refuses="max_turns=None or max_consecutive_auto_reply=None",
        silent_on="a finite limit",
        cwe=("CWE-835", "CWE-770"),
        asi=("ASI08",),
        references=(*_OWASP, "https://microsoft.github.io/autogen/0.2/docs/tutorial/conversation-patterns/"),
        default=ALLOW,
    ),
    Rule(
        id="bounds-recursion-limit-high",
        pack="bounds",
        title="Recursion limit of 1000 or more",
        why="A limit in the thousands is no limit for a graph stuck in a cycle: cost and side effects pile up first.",
        kinds=("python", "js"),
        scan=_recursion,
        fix="keep recursion_limit at the framework default or the smallest number the graph needs, and add a stop condition.",
        refuses="recursion_limit (recursionLimit) set to an integer of 1000 or more",
        silent_on="recursion_limit below 1000",
        cwe=("CWE-674", "CWE-770"),
        asi=("ASI08",),
        references=(*_OWASP, "https://langchain-ai.github.io/langgraph/concepts/low_level/#recursion-limit"),
        default=ALLOW,
    ),
    Rule(
        id="bounds-crewai-max-iter-high",
        pack="bounds",
        title="CrewAI max_iter of 100 or more",
        why="Hundreds of iterations per task multiply cost and repeat side effects when the agent cannot finish.",
        kinds=("python",),
        scan=_max_iter,
        fix="keep max_iter near the default of 20 and let the agent report failure instead of iterating.",
        refuses="max_iter set to an integer of 100 or more",
        silent_on="max_iter below 100",
        cwe=("CWE-770",),
        asi=("ASI08",),
        references=(*_OWASP, "https://docs.crewai.com/concepts/agents"),
        default=ALLOW,
    ),
)
