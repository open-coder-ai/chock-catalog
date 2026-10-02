"""Say what a file is from its content, not its name: candidate kinds with a confidence each, never one silent guess.

A renamed file must not dodge a scanner: a Dockerfile saved as build.txt, a workflow outside
.github/workflows, a shell script without .sh, a Kubernetes manifest named .conf. `sniff(data)`
reads the bytes only, whatever the file is called, and returns every kind the content supports.
No candidate is an explicit unknown; a file over the limit is an explicit too-large with none.

Signals, read over the whole text (no first-N-lines window: padding cannot push a key out of view).
Keys are top-level: of a YAML document's root mapping, of a root sequence item, or of JSON's root
object. `low` is the same keys found anywhere outside full-line comments (nested, split across
documents, in a flow mapping, JSON with comments, a trailing comment, through an alias), any
key-like token this reader cannot name anywhere (which may be any key), or a unit whose keys this
reader cannot all name (an explicit `?` key, an alias of an anchor not one simple scalar, or reused),
since such a key may be any key.
  kubernetes      high: apiVersion + kind
  cloudformation  high: AWSTemplateFormatVersion, or Transform with AWS::Serverless in the text
                  medium: Resources with a `Type: X::Y::` value in the text; low: Resources
  openapi         high: openapi, or swagger
  compose         medium: services
  github-actions  high: on + jobs
  ansible         high: hosts + tasks; medium: hosts + roles, pre_tasks, post_tasks or handlers
  mcp-config      high: mcpServers
  dockerfile      high: the first instruction (after parser directives, comments and ARG) is FROM
                  low: a FROM line and a RUN, CMD, ENTRYPOINT, COPY or ADD line anywhere
  script          high: a `#!` first line
  shell           high: the #! command is a shell (through env, its options and -S quoting)
                  low: a later word of the #! line is a shell (sudo bash, nice sh)
Not seen: a script with no shebang; a GitHub composite action, an Ansible task file or an
import_playbook file (none has its kind's keys); keys a `<<` merge brings in are found only as low.
Bytes are read with their BOM's encoding (UTF-8/16/32), else UTF-16/32 by YAML's NUL pattern,
else UTF-8. `content` is binary when the text holds a NUL, undecodable when the bytes are not
valid in that encoding; both are still sniffed (lossily, and also as UTF-8 when the encoding was
not UTF-8), since a shell runs a script whose NUL comes after its first line.
"""

from __future__ import annotations

import codecs
import re
from collections import deque
from typing import NamedTuple

from .sniff_keys import UNNAMED, Unit, loose_keys, units

LIMIT = 1 << 20
MAX_LIMIT = 1 << 26
TEXT, UNDECODABLE, BINARY, TOO_LARGE = "text", "undecodable", "binary", "too-large"
HIGH, MEDIUM, LOW = "high", "medium", "low"
KINDS = frozenset({"kubernetes", "cloudformation", "openapi", "compose", "github-actions", "ansible", "mcp-config"})
KINDS |= {"dockerfile", "script", "shell"}
RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}
BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)
SERVERLESS = re.compile(r"AWS::Serverless")
RESOURCE_TYPE = re.compile(r"""\bType["']?\s*+:\s*+["']?[A-Za-z0-9]++::[A-Za-z0-9]++::""")
#: (kind, confidence, keys one unit must hold, pattern the whole text must also match)
MAPPED = (
    ("kubernetes", HIGH, ("apiVersion", "kind"), None),
    ("cloudformation", HIGH, ("AWSTemplateFormatVersion",), None),
    ("cloudformation", HIGH, ("Transform",), SERVERLESS),
    ("cloudformation", MEDIUM, ("Resources",), RESOURCE_TYPE),
    ("cloudformation", LOW, ("Resources",), None),
    ("openapi", HIGH, ("openapi",), None),
    ("openapi", HIGH, ("swagger",), None),
    ("compose", MEDIUM, ("services",), None),
    ("github-actions", HIGH, ("on", "jobs"), None),
    ("ansible", HIGH, ("hosts", "tasks"), None),
    *(("ansible", MEDIUM, ("hosts", key), None) for key in ("roles", "pre_tasks", "post_tasks", "handlers")),
    ("mcp-config", HIGH, ("mcpServers",), None),
)
SHELL = re.compile(r"(?:a|ba|da|k|mk|pdk|lk|ok|lok|o|z|ya|po|rba|c|tc|fi|hu|bo|j)?sh(?:[-.\d][\w.-]*+)?")
MULTICALL = frozenset({"busybox", "toybox"})
ENV_VALUE = frozenset("uCP")
ENV_QUOTES = re.compile(r"""["']""")
DIRECTIVE = re.compile(r"#[ \t]*+([A-Za-z]++)[ \t]*+=[ \t]*+(\S*+)[ \t]*+")
#: The kernel reads at most 256 bytes of a #! line (BINPRM_BUF_SIZE); more is never an interpreter.
SHEBANG_MAX = 4096
DOCKER_BODY = frozenset({"RUN", "CMD", "ENTRYPOINT", "COPY", "ADD"})


class Candidate(NamedTuple):
    """One kind the content supports, how strongly, and the signal that matched."""

    kind: str
    confidence: str
    signal: str


class Sniff(NamedTuple):
    """What the content is: `candidates` empty means unknown, or too large to read when `content` says so."""

    content: str
    encoding: str | None
    candidates: tuple[Candidate, ...]
    interpreter: tuple[str, ...]

    @property
    def unknown(self) -> bool:
        """Read in full and no kind found; a too-large file is not unknown, it is unread."""
        return self.content != TOO_LARGE and not self.candidates

    def kinds(self, at_least: str = LOW) -> frozenset[str]:
        """The candidate kinds at or above a confidence."""
        return frozenset(c.kind for c in self.candidates if RANK[c.confidence] >= RANK[at_least])


def sniff(data: bytes, limit: int = LIMIT) -> Sniff:
    """Every kind `data` supports; more than `limit` bytes is TOO_LARGE, read no further."""
    if type(limit) is not int or not 0 <= limit <= MAX_LIMIT:
        msg = f"limit must be 0..{MAX_LIMIT}, not {limit}"
        raise ValueError(msg)
    if len(data) > limit:
        return Sniff(TOO_LARGE, None, (), ())
    encoding, skip = _encoding(data)
    try:
        text = data[skip:].decode(encoding)
    except UnicodeDecodeError:
        text, content = data[skip:].decode(encoding, "replace"), UNDECODABLE
    else:
        content = TEXT
    if "\0" in text:
        content = BINARY
    texts = [text] if encoding == "utf-8" else [text, data.decode("utf-8", "replace")]
    best: dict[str, Candidate] = {}
    for found in texts:
        for candidate in _candidates(found):
            held = best.get(candidate.kind)
            if held is None or RANK[candidate.confidence] > RANK[held.confidence]:
                best[candidate.kind] = candidate
    label = encoding + ("-bom" if skip else "")
    ranked = tuple(sorted(best.values(), key=lambda c: (-RANK[c.confidence], c.kind)))
    return Sniff(content, label, ranked, interpreter(text))


def interpreter(text: str) -> tuple[str, ...]:
    """The command a `#!` first line runs, through `env` and its options (`-S` included), and its words."""
    first = text[:SHEBANG_MAX].split("\n", 1)[0].rstrip("\r")
    if not first.startswith("#!"):
        return ()
    words = first[2:].split()
    if not words:
        return ()
    if _base(words[0]) != "env":
        return (_base(words[0]), *words[1:])
    return _after_env(words[1:])


def _after_env(words: list[str]) -> tuple[str, ...]:
    """The command env runs: options, their values and NAME=VALUE pairs skipped; `-S` splits on.

    Quotes and `\\_` are dropped first, as `env -S` would: a quoted shell name is still that shell.
    """
    queue = deque(ENV_QUOTES.sub("", " ".join(words)).replace("\\_", " ").split())
    while queue:
        word = queue.popleft()
        if word == "--":
            break
        if word.startswith("--"):
            _long_option(word, queue)
        elif word.startswith("-"):
            _short_options(word[1:], queue)
        elif "=" not in word:
            return (_base(word), *queue)
    return (_base(queue.popleft()), *queue) if queue else ("env",)


def _long_option(word: str, queue: deque[str]) -> None:
    name, eq, value = word.partition("=")
    if name == "--split-string" and eq:
        queue.appendleft(value)
    elif name in ("--unset", "--chdir") and not eq and queue:
        queue.popleft()


def _short_options(flags: str, queue: deque[str]) -> None:
    for at, flag in enumerate(flags):
        if flag in ENV_VALUE:
            if at + 1 == len(flags) and queue:
                queue.popleft()
            return
        if flag == "S":
            if at + 1 < len(flags):
                queue.appendleft(flags[at + 1 :])
            return


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def _encoding(data: bytes) -> tuple[str, int]:
    """The codec the bytes are in and the length of their BOM, by BOM, else YAML's NUL pattern."""
    for bom, name in BOMS:
        if data.startswith(bom):
            return name, len(bom)
    head = data[:4]
    if len(head) == 4 and head[:3] == b"\0\0\0" and head[3]:  # noqa: PLR2004 -- four bytes of UTF-32
        return "utf-32-be", 0
    if len(head) == 4 and head[0] and head[1:] == b"\0\0\0":  # noqa: PLR2004 -- four bytes of UTF-32
        return "utf-32-le", 0
    if len(head) >= 2 and not head[0] and head[1]:  # noqa: PLR2004 -- two bytes of UTF-16
        return "utf-16-be", 0
    if len(head) >= 2 and head[0] and not head[1]:  # noqa: PLR2004 -- two bytes of UTF-16
        return "utf-16-le", 0
    return "utf-8", 0


def _candidates(text: str) -> list[Candidate]:
    found = _mapped(text, list(dict.fromkeys(units(text))))  # distinct, in order: a file of `- ` lines holds one
    instructions = _instructions(text)
    if _first_is_from(instructions):
        found.append(Candidate("dockerfile", HIGH, "first instruction FROM"))
    elif _docker_lines(instructions + text.split("\n")):
        found.append(Candidate("dockerfile", LOW, "FROM and build instruction lines"))
    if command := interpreter(text):
        found.append(Candidate("script", HIGH, f"#! {command[0]}"))
        if _is_shell(command):
            found.append(Candidate("shell", HIGH, f"#! {' '.join(command[:2])}"))
        elif any(SHELL.fullmatch(_base(word).lower()) for word in command[1:]):
            found.append(Candidate("shell", LOW, "a shell named later in the #! line"))
    return found


def _mapped(text: str, found_units: list[Unit]) -> list[Candidate]:
    loose: set[str] | None = None
    out: list[Candidate] = []
    for kind, confidence, keys, pattern in MAPPED:
        if pattern is not None and not pattern.search(text):
            continue
        signal = "+".join(keys)
        for unit in found_units:
            missing = len(set(keys) - unit.keys)
            if not missing:
                out.append(Candidate(kind, confidence, f"top-level {signal}"))
            elif missing <= unit.opaque:
                out.append(Candidate(kind, LOW, f"top-level {signal}, some keys unnamed"))
        loose = loose_keys(text) if loose is None else loose
        if set(keys) <= loose:
            out.append(Candidate(kind, LOW, f"{signal} anywhere"))
        elif UNNAMED in loose:
            out.append(Candidate(kind, LOW, f"{signal} anywhere, or a key it cannot name"))
    return out


def _instructions(text: str) -> list[str]:
    """Dockerfile logical lines: parser directives read, comments and blank lines dropped, continuations joined."""
    escape, directives, held, out = "\\", True, [], []
    for raw in text.split("\n"):
        line = raw.strip()
        if directives and (directive := DIRECTIVE.fullmatch(line)):
            if directive.group(1).lower() == "escape" and directive.group(2) in ("\\", "`"):
                escape = directive.group(2)
            continue
        directives = False
        if not line or line.startswith("#"):
            continue
        segment = raw.rstrip() if held else line
        if segment.endswith(escape):
            held.append(segment[:-1])
        else:
            out.append("".join([*held, segment]))
            held = []
    return [*out, "".join(held)] if held else out


def _first_is_from(instructions: list[str]) -> bool:
    for instruction in instructions:
        word = instruction.split(None, 1)
        if word and word[0].upper() != "ARG":
            return word[0].upper() == "FROM" and len(word) > 1
    return False


def _docker_lines(lines: list[str]) -> bool:
    words = {split[0].upper() for line in lines if len(split := line.split(None, 1)) > 1}
    return "FROM" in words and bool(words & DOCKER_BODY)


def _is_shell(command: tuple[str, ...]) -> bool:
    name = command[1] if command[0] in MULTICALL and len(command) > 1 else command[0]
    return SHELL.fullmatch(_base(name).lower()) is not None
