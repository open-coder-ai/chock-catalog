"""Agent CLIs started with their safety checks off, in any surface, shell, workflow or build file.

The text is read once, character by character, as a shell reads it: quotes span lines and keep their
words (a flag passed in quotes still counts) but not their separators; a backslash-newline joins lines;
`;`, `|`, `&` and newlines end a statement, except the `&` of a redirect (`2>&1`, `&>`); `#` at the start
of a word begins a comment. Each raw line is read too, and then, if neither found one, the file as a whole,
so no quote the reader misjudges and no line break hides a flag.
The time grows with the text, never with how it is quoted.
"""

from __future__ import annotations

import re

from devenv.core import Collector, norm

_PREFIX = r"(?<![\w.@/\\-])(?:[\w@.~-]*[/\\])*"
_CLI = re.compile(
    rf"(?i){_PREFIX}(claude(?:-code)?|codex|gemini(?:-cli)?|cursor-agent|copilot|qwen(?:-code)?"
    r"|opencode|amp|aider|goose|crush|auggie|droid|kiro-cli)(?:\.exe|\.cmd)?(?![\w.-])"
)
_FLAGS = re.compile(
    r"(?i)(?<![\w-])(?:--dangerously-skip-permissions|--allow-dangerously-skip-permissions"
    r"|--dangerously-bypass-approvals-and-sandbox|--permission-mode[=\s]+bypasspermissions|--yolo|--full-auto"
    r"|--approval-mode[=\s]+yolo|--allow-all-tools|--allow-all-paths|--yes-always"
    r"|(?:--sandbox|-s)[=\s]+danger-full-access"
    r"|(?:-c|--config)[=\s]+(?:approval_policy\W*=\W*never|sandbox_mode\W*=\W*danger-full-access))(?![\w-])"
)
#: Short flags that skip checks only for one CLI: (that CLI, the flag).
_SHORT = [
    (re.compile(rf"(?i){_PREFIX}gemini(?:-cli)?(?:\.exe|\.cmd)?(?![\w.-])"), re.compile(r"(?<![\w-])-y(?![\w-])")),
    (
        re.compile(rf"(?i){_PREFIX}cursor-agent(?:\.exe|\.cmd)?(?![\w.-])"),
        re.compile(r"(?<![\w-])(?:-f|--force)(?![\w-])"),
    ),
]
_SEPARATORS = frozenset(";|&\n")


def statements(text: str) -> list[tuple[int, str]]:  # noqa: C901 -- one arm per shell character class
    """(line the statement starts on, its words) for every statement in `text`."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    line = start = 1
    quote = ""
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        nxt = text[index + 1] if index + 1 < size else ""
        line += char == "\n"
        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"' and nxt:
                buf.append(" " if nxt in _SEPARATORS else nxt)
                line += nxt == "\n"
                index += 1
            else:
                buf.append(" " if char in _SEPARATORS else char)
        elif char == "\\" and nxt:
            # Kept as written so Windows paths survive; `unsafe` also reads the statement with them removed.
            crlf = nxt == "\r" and text[index + 2 : index + 3] == "\n"
            buf.append(" " if nxt == "\n" or crlf else char + nxt)
            line += nxt == "\n" or crlf
            index += 1 + crlf
        elif char in "\"'":
            quote = char
        elif char == "#" and (not buf or buf[-1] in " \t"):
            while index + 1 < size and text[index + 1] != "\n":
                index += 1
        elif char == "&" and (nxt == ">" or (buf and buf[-1] in "<>")):
            buf.append(char)
        elif char in _SEPARATORS:
            out.append((start, "".join(buf)))
            buf, start = [], line
        elif char != "\r":
            buf.append(char)
        index += 1
    out.append((start, "".join(buf)))
    return [(number, words) for number, words in out if words.strip()]


def unsafe(statement: str) -> bool:
    """Whether an agent CLI in the statement is followed by a flag that skips its checks."""
    first = _CLI.search(statement)
    if first is None:
        return False
    if _FLAGS.search(statement, first.end()):
        return True
    for cli, flag in _SHORT:
        own = cli.search(statement)
        if own and flag.search(statement, own.end()):
            return True
    return False


def spawns(c: Collector) -> None:
    """Report a statement the shell reader finds, and also any raw line (quotes and comments left as written,
    only a line that is wholly a comment skipped): a quote the reader counts that the file's language does not
    (a heredoc, `$'...'`, a YAML plain value) can then hide nothing."""
    seen: set[int] = set()
    for number, statement in statements(c.text):
        if unsafe(statement) or ("\\" in statement and unsafe(statement.replace("\\", ""))):
            message = "an agent CLI is started with its safety checks off"
            c.add("dev-agent-spawn", f"spawn={norm(statement.strip())}", message, line=number)
            seen.add(number)
    code = [(number, line) for number, line in enumerate(c.lines, 1) if not line.lstrip().startswith("#")]
    for number, line in code:
        if number not in seen and unsafe(line):
            message = "an agent CLI is started with its safety checks off"
            c.add("dev-agent-spawn", f"spawn-line={norm(line.strip())}", message, line=number)
            seen.add(number)
    if not seen:
        _whole_file(c, code)


def _whole_file(c: Collector, code: list[tuple[int, str]]) -> None:
    """Last pass, with no reading of quotes or continuations at all: an agent CLI anywhere in the file and a
    skip flag anywhere after it. It errs toward reporting, so no way of splitting the two across lines hides one."""
    joined = " ".join(line for _, line in code)
    first = _CLI.search(joined)
    flag = _FLAGS.search(joined, first.end()) if first else None
    if first is None or flag is None:
        for cli, short in _SHORT:
            own = cli.search(joined)
            first, flag = (own, short.search(joined, own.end())) if own else (first, None)
            if flag:
                break
    if first is not None and flag is not None:
        name = re.split(r"[/\\]", first.group(0))[-1].lower()
        number = next((n for n, line in code if name in line.lower()), 1)
        message = "an agent CLI and a flag that skips its checks appear in this file (judged across lines)"
        c.add("dev-agent-spawn", f"spawn-file={first.group(0).lower()}..{flag.group(0).lower()}", message, line=number)
