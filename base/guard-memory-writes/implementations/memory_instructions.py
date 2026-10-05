"""Ask-tier findings in an agent-memory file (OWASP ASI06): an instruction-shaped line, a URL host off the allowlist, an encoded blob."""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections import Counter
from pathlib import Path

from chock_scan import hostmatch, safe_read, urls

ADVICE = "Store facts, not instructions; never persist text that came from a fetched page or tool result."
ALLOWLIST = ".chock/egress-allowlist.txt"
#: Hosts a memory line may name without a question: this machine and the reserved example names.
EXEMPT = hostmatch.parse_allowlist(
    "localhost\n127.0.0.1\n[::1]\nexample.com\n*.example.com\nexample.org\n*.example.org\nexample.net\n*.example.net\n"
)
MAX_URLS = 50

# scan-instruction-files' lexicon.json patterns, verbatim; tests/policies/test_guard_memory_writes_instructions.py
# fails when one drifts from the lexicon it was copied from.
NP02 = {
    "negation": r"""\b(?:never|not|no|nor|don't|dont|do not|does not|doesn't|must not|mustn't|should not|shouldn't|cannot|can't|won't|will not|avoid|refuse|forbid|prohibit|block|prevent|deny|reject|disallow|instead of|rather than)\b""",
    "encourager": r"""\b(?:no need to|not necessary to|not required to|no reason not to|don't hesitate to|do not hesitate to|never hesitate to|(?:don't|do not|never|not) (?:forget|hesitate|fail)\b(?: to)?|feel free to|not a problem to|no problem to|nothing wrong with|not wrong to|don't be afraid to|do not be afraid to|no matter (?:what|how|when|who)|no exceptions?|without exception|not optional|non-negotiable|no excuses)\b""",
    "segment_break": r"""[.!?](?=\s|$)|;|\bbut\b""",
    "net_tool": r"""\b(?:curl|wget|nc|ncat|netcat|socat|invoke-webrequest|invoke-restmethod|iwr|irm|scp|rsync|sftp|ftp|telnet|httpie|xh|http(?!s?:))\b""",
}
NEGATION, ENCOURAGER, SEGMENT, NET_TOOL = (
    re.compile(NP02[k]) for k in ("negation", "encourager", "segment_break", "net_tool")
)

# Memory-specific weights. A sentence asks when what it addresses to the agent (STRONG 3, MEDIUM 2) and what it asks
# for (a pipe into an interpreter 3; a network tool, a shell verb or a URL 2) add up to THRESHOLD, and no negation
# sits between the two unless an encourager cancels it.
STRONG = re.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?"
    r"(?:previous|prior|above|earlier|system|safety|security|existing|standing)\s+"
    r"(?:instructions?|rules?|guidelines?|prompts?|polic(?:y|ies)|constraints?)\b"
    r"|\bfrom (?:now|here|this point) on(?:wards?)?\b"
    r"|\b(?:at the (?:start|beginning) of|before|after|on|in) (?:every|each|any|all) "
    r"(?:session|conversation|task|turn|reply|response|answer|message|command|tool call|startup|run)s?\b"
)
MEDIUM = re.compile(
    r"\byou (?:must|should|shall|need to|have to|are to|will)\b"
    r"|\b(?:make sure|be sure|ensure) (?:to|that you|you)\b"
    r"|\bremember to\b|\bmust always\b|\bwhenever\b|\bevery time\b|\beach time\b|\bplease\b"
    r"|(?:^|[:;,]\s*|\byou\s+|\bplease\s+|\b(?:agent|assistant|claude|ai|model)\s*,?\s+)always(?![-\w])"
    r"|^(?:run|execute|fetch|download|visit|open|load|follow|send|post|upload|call|pipe|install)\s"
)
PIPE_TO_SHELL = re.compile(
    r"\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[\d.]*|node|perl|ruby|php|iex|pwsh|powershell)\b"
)
SHELL = re.compile(
    r"\b(?:sudo|ssh|chmod|chown|powershell|pwsh|iex|git\s+push|npm\s+publish|twine\s+upload"
    r"|docker\s+(?:run|login|push)|(?:ba|z)?sh\s+-c|base64\s+(?:-d|--decode))\b|\brm\s+-\w*[rf]|\beval\s+[\"'$`(]"
)
SCHEME = re.compile(r"\b(?:https?|ftp|sftp|wss?)://")
THRESHOLD = 4

URL = re.compile(r"(?:https?|ftp|sftp|wss?)://(?:\[[0-9a-f:.]+\]|[^\s<>\"'`)\]])[^\s<>\"'`)\]]*", re.IGNORECASE)
TRAILING = ".,;:!?"
BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{48,}={0,2}(?![A-Za-z0-9+/_-])")
HEX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{66,}(?![0-9A-Fa-f])")
MIN_ENTROPY = 4.5

BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
BLOCK_START = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s|#|\||>)")
FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})")
EMPHASIS = re.compile(r"\*++|~~|(?<!\w)_++|(?<!_)_++(?!\w)")
SPACE = re.compile(r"\s+")
DROPPED = frozenset({"Cf", "Mn", "Me", "Cc"})
QUOTES = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u201b": "'",
        "\u2032": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": " - ",
        "\u2014": " - ",
    }
)
# Cyrillic and Greek letters that read as Latin ones, so a lookalike cannot hide a phrase (never applied to a URL).
LOOKALIKES = str.maketrans(
    dict(
        zip(
            "\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u0455\u043a\u043c\u043d\u0442",
            "aeopcxyijskmnt",
            strict=True,
        )
    )
    | dict(zip("\u03b1\u03b5\u03bf\u03c1\u03bd\u03b9\u03ba\u03c4\u03c7", "aeopviktx", strict=True))
)


def strip_format(text: str) -> str:
    """The text without format, combining and control characters; whitespace among them stays a space."""
    return "".join(c if unicodedata.category(c) not in DROPPED else " " if c.isspace() else "" for c in text)


def fold(text: str) -> str:
    """Casefolded text as matching reads it: compatibility forms and lookalike letters as Latin, no emphasis or backticks."""
    text = strip_format(unicodedata.normalize("NFKD", text.translate(QUOTES))).casefold().translate(LOOKALIKES)
    return SPACE.sub(" ", EMPHASIS.sub("", text.replace("`", ""))).strip()


def statements(text: str) -> list[tuple[int, str]]:
    """(first line, text) of each statement: a list item, heading or table row, or a paragraph with its wraps joined."""
    out: list[tuple[int, str]] = []
    run: list[str] = []
    first = 0
    for number, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line) or not line.strip():
            run = _close(out, first, run)
        elif run and not BLOCK_START.match(line) and not run[0].startswith("#"):
            run.append(line.strip())
        else:
            _close(out, first, run)
            first, run = number, [BULLET.sub("", line).strip()]
    _close(out, first, run)
    return out


def _close(out: list[tuple[int, str]], first: int, run: list[str]) -> list[str]:
    if run:
        out.append((first, " ".join(run)))
    return []


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _shown(text: str, limit: int = 100) -> str:
    return "".join(c if c.isprintable() else " " for c in " ".join(text.split()))[:limit]


def _row(rule: str, path: str, number: int, key: str, message: str) -> dict:
    return {"key": f"{rule}|{key}", "path": path, "line": number, "rule": rule, "message": message}


def _asked(sentence: str) -> list[tuple[int, int, int]]:
    """(weight, start, end) of what a sentence asks for."""
    pipes = [(3, m.start(), m.end()) for m in PIPE_TO_SHELL.finditer(sentence)]
    others = (NET_TOOL, SHELL, SCHEME)
    return pipes + [(2, m.start(), m.end()) for p in others for m in p.finditer(sentence)]


def _addressed(sentence: str) -> list[tuple[int, int, int]]:
    """(weight, start, end) of each cue that the sentence speaks to the agent."""
    return [(3, m.start(), m.end()) for m in STRONG.finditer(sentence)] + [
        (2, m.start(), m.end()) for m in MEDIUM.finditer(sentence)
    ]


def _prohibits(sentence: str, first: tuple[int, int], second: tuple[int, int]) -> bool:
    """Whether a negation, not cancelled by an encourager, sits between the cue and what it asks for."""
    left, right = sorted((first, second))
    between = sentence[left[1] : right[0]]
    return bool(NEGATION.search(between)) and not ENCOURAGER.search(between)


def instructs(statement: str) -> bool:
    """Whether one sentence of the statement tells the agent to run a command or fetch a URL."""
    for sentence in map(str.strip, SEGMENT.split(fold(statement))):
        asked = _asked(sentence)
        for cue_weight, cue_start, cue_end in _addressed(sentence):
            for weight, start, end in asked:
                if cue_weight + weight >= THRESHOLD and not _prohibits(sentence, (cue_start, cue_end), (start, end)):
                    return True
    return False


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def blobs(line: str) -> list[str]:
    """Each run of an encoded blob in a line: base64 of mixed case with digits, or hex past a digest's length."""
    runs = [m.group() for m in BASE64.finditer(line) if _opaque(m.group())]
    return runs + [m.group() for m in HEX.finditer(line)]


def _opaque(run: str) -> bool:
    classes = (any(c.isupper() for c in run), any(c.islower() for c in run), any(c.isdigit() for c in run))
    return all(classes) and sum(run.count(c) for c in "/-_") < len(run) // 16 and entropy(run) >= MIN_ENTROPY


def allowlist(root: str) -> tuple[hostmatch.Entry, ...] | None:
    """The repo's host allowlist, or None when it has none or its file cannot be read (then the host check is off)."""
    path = Path(root) / ALLOWLIST
    try:
        return hostmatch.parse_allowlist(safe_read.read_text(path)) or None
    except (OSError, safe_read.UnreadableError, hostmatch.UnparseableError):
        return None


def hosts(statement: str) -> list[tuple[str, bool]]:
    """(host as written, whether it is unreadable) of each URL in a statement, in order."""
    plain = unicodedata.normalize("NFKC", strip_format(statement))
    out = []
    for match in URL.finditer(plain):
        text = match.group().rstrip(TRAILING)
        try:
            out.append((urls.parse_url(text).host.name, False))
        except (urls.UnparseableError, ValueError):
            out.append((text.split("/", 3)[2][:80], True))
    return out[:MAX_URLS]


def off_list(name: str, entries: tuple[hostmatch.Entry, ...]) -> bool:
    """Whether a readable host is neither exempt nor on the repo's allowlist."""
    if any(hostmatch.matches(name, e) for e in EXEMPT):
        return False
    return not any(hostmatch.matches(name, e) for e in entries)


def ask_rows(path: str, text: str, entries: tuple[hostmatch.Entry, ...] | None, skip: set[int]) -> list[dict]:
    """Every ask-tier finding in one memory file, in line order; `skip` holds the lines a secret already refuses."""
    out = []
    for number, statement in statements(text):
        digest = _digest(fold(statement))
        if instructs(statement):
            out.append(
                _row("instruction", path, number, digest, f"reads as an instruction to the agent: {_shown(statement)}")
            )
        for name, unreadable in hosts(statement) if entries else ():
            if unreadable or off_list(name, entries):
                kind = "URL host that cannot be read one way" if unreadable else "URL host"
                out.append(
                    _row("url-host", path, number, f"{name}|{digest}", f"{kind} {name!r}: not on the repo's allowlist")
                )
    for number, line in enumerate(text.splitlines(), 1):
        out += [
            _row("blob", path, number, _digest(run), f"an encoded blob of {len(run)} characters")
            for run in blobs(strip_format(line))
            if number not in skip
        ]
    return sorted(out, key=lambda row: row["line"])
