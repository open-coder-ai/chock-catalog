"""A stream, reader, connection, statement, socket or executor opened as a local and never
closed leaks a file handle or a thread pool every time this method runs -- eventually the
process runs out of descriptors or threads for a mistake invisible in any one request."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import Method, methods
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "resources-unclosed-closeable"

_FACTS = facts("resources")["unclosed"]

_CONSTRUCTOR_ALT = r"new\s+(?:" + "|".join(re.escape(c) for c in _FACTS["constructors"]) + r")\s*\("
_FACTORY_ALT = "|".join(re.escape(c) for c in _FACTS["factory_calls"])
_METHOD_ALT = r"\w+(?:\.\w+)*\.(?:" + "|".join(re.escape(m) for m in _FACTS["method_names"]) + r")\s*\("
_EXEC_ALT = "|".join(re.escape(c) for c in _FACTS["executor_factories"])
_OPEN_ALT = f"(?:{_CONSTRUCTOR_ALT}|{_FACTORY_ALT}|{_METHOD_ALT}|{_EXEC_ALT})"

_DECL = re.compile(rf"(?:^|;)\s*(?:final\s+)?[A-Za-z_$][\w.$]*(?:<[^<>]*>)?(?:\[\])?\s+(\w+)\s*=\s*({_OPEN_ALT})")

_MESSAGE = (
    "{name} is opened here but this method never {verb}s it on every path -- no try-with-resources "
    "and no {verb}() in a finally. Declare it in a try-with-resources header (or {verb}() it in a "
    f"finally block) so it is released even when an exception is thrown. 'chock: allow {RULE_ID}' "
    "on this line if ownership genuinely passes elsewhere."
)


def _blanked_body(text: FileText, method: Method) -> list[tuple[int, str, str]]:
    """Each body line as (line number, the line as written, the line with comments/literals blanked)."""
    code_lines = code(text)
    return [
        (line_no, raw, code_lines[line_no - 1] if 0 < line_no <= len(code_lines) else raw)
        for line_no, raw in method.body
    ]


def _try_header_lines(blanked_body: list[tuple[int, str, str]]) -> set[int]:
    """Line numbers inside a `try (...)` resource header -- declared there, not left unclosed."""
    covered: set[int] = set()
    depth = 0
    active = False
    for line_no, _raw, line in blanked_body:
        if not active:
            idx = line.find("try (")
            if idx == -1:
                continue
            active = True
            covered.add(line_no)
            segment = line[idx + len("try ") :]
            depth = segment.count("(") - segment.count(")")
            if depth <= 0:
                active = False
            continue
        covered.add(line_no)
        depth += line.count("(") - line.count(")")
        if depth <= 0:
            active = False
    return covered


def _escapes(
    name: str, blanked_body: list[tuple[int, str, str]], decl_line_no: int, covered: set[int], release: list[str]
) -> bool:
    """Whether the method itself accounts for `name`: released, returned, stored, or handed off."""
    word = re.escape(name)
    released = [rf"\b{word}\.{re.escape(r)}" for r in release]
    for line_no, _raw, line in blanked_body:
        if line_no <= decl_line_no:
            continue
        if any(re.search(pattern, line) for pattern in released):
            return True
        if line_no in covered and re.search(rf"\b{word}\b", line):
            return True  # wrapped into a later try-with-resources header -- that TWR releases it
        if re.search(rf"\breturn\s+{word}\b", line):
            return True
        if re.search(rf"=\s*{word}\s*;", line):
            return True
        if re.search(rf"new\s+\w+\([^)]*\b{word}\b", line):
            return True
    return False


def _kind(call: str) -> tuple[bool, list[str]]:
    """Whether `call` opened an executor, and the release-method names that satisfy it."""
    if call in _FACTS["executor_factories"]:
        return True, _FACTS["executor_release"]
    return False, _FACTS["default_release"]


def _skip_unscoped_scanner(call: str, line: str) -> bool:
    """A `Scanner` over a String or `System.in` is not a file handle -- only a File/Path source is."""
    return "Scanner" in call and not any(marker in line for marker in _FACTS["scanner_source_markers"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every local Closeable/ExecutorService opened outside try-with-resources with no release call."""
    for method in methods(text):
        blanked_body = _blanked_body(text, method)
        covered = _try_header_lines(blanked_body)
        for line_no, raw, line in blanked_body:
            if line_no in covered:
                continue
            match = _DECL.search(line)
            if not match:
                continue
            if not (line.rstrip().endswith(";") and line.count("(") == line.count(")")):
                continue
            name, call = match.group(1), match.group(2)
            if _skip_unscoped_scanner(call, line):
                continue
            is_exec, release = _kind(call)
            if _escapes(name, blanked_body, line_no, covered, release):
                continue
            verb = "shutdown" if is_exec else "close"
            yield Finding(RULE_ID, text.path, line_no, raw, _MESSAGE.format(name=name, verb=verb))


RULE = Rule(
    id=RULE_ID,
    pack="resources",
    title="Closeable or executor opened without try-with-resources or a finally close",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(declare): a local FileInputStream|FileOutputStream|FileReader|FileWriter|"
        "BufferedReader|RandomAccessFile|ZipFile|JarFile|Socket|ServerSocket|Files.newInputStream|"
        "DriverManager.getConnection|dataSource.getConnection|conn.createStatement|"
        "conn.prepareStatement|Executors.newFixedThreadPool outside a try-with-resources header "
        "with no close()/shutdown() in a finally -- use try-with-resources"
    ),
    refuses=(
        "a stream, reader, writer, connection, statement, socket, or ExecutorService assigned to a "
        "local outside a `try (` header, with no close()/shutdown() call anywhere later in the method"
    ),
    silent_on=(
        "the same resource declared inside a try-with-resources header (single- or multi-resource, "
        "including a raw reader wrapped and closed via an outer BufferedReader's own header); a "
        "resource explicitly closed or shut down later in the method; one returned to the caller, "
        "stored to a field, or handed to another constructor; a Scanner over a String or System.in"
    ),
    cwe=("CWE-772", "CWE-775"),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-2095/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#obl-method-may-fail-to-clean-up-stream-or-resource-obl-unsatisfied-obligation",
    ),
)
