#!/usr/bin/env python3
"""Report hidden text and data-carrying URLs in Markdown, HTML, SVG, XML and Word files; the engine keeps what a change adds."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

# The scanners ship beside this script. A missing or broken copy raises here, and the runner treats an
# exit it did not ask for as undecided, which takes the declared action. No bytecode cache is written:
# the gate is read_only in the repository it judges.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from hiddenscan import links as hidden_urls  # noqa: E402 -- after the path and cache setup
from hiddenscan import markdown as hidden_text  # noqa: E402
from hiddenscan import markup as hidden_html  # noqa: E402
from hiddenscan import word as hidden_docx  # noqa: E402
from hiddenscan.vocab import normalized, vocab  # noqa: E402

ALLOW, BLOCK, UNREADABLE, ASK, WARN = 0, 1, 2, 3, 4
#: D15: the policy ships in observe and warns on every finding. A separate PR sets this to False, and the
#: gate then blocks a URL whose query names a secret and a URL dictionary, and asks for the rest.
OBSERVE = True
MAX_FINDINGS = 10000
#: A text file past this is not parsed (the 30-second budget covers the baseline run too); it is
#: reported, keyed by its whole text, so every change to it is new.
MAX_TEXT = 1 << 20
#: A KaTeX finding is keyed by the command and what follows it, not by its whole line.
KATEX_WINDOW = 120
SHOWN = 50
MARKDOWN = {".md", ".mdx", ".markdown", ".mdc"}
MARKUP = {".html", ".htm", ".xhtml", ".svg", ".xml"}
#: Agent instruction files with no Markdown suffix (and llms.txt, Markdown for agents), read as Markdown.
RULE_FILES = re.compile(r"(^|/)(\.cursorrules|\.windsurfrules|\.clinerules|\.goosehints|llms(-full)?\.txt)$")
#: Directories of agent instructions and issue or pull-request templates: every text file there.
RULE_DIRS = re.compile(
    r"(^|/)(\.cursor/rules|\.roo/rules|\.kiro/steering|\.clinerules|\.github/(instructions|prompts|agents"
    r"|ISSUE_TEMPLATE|PULL_REQUEST_TEMPLATE|DISCUSSION_TEMPLATE))/"
)
DOCS = re.compile(r"(^|/)docs?/[^/]+(/[^/]+)*\.(rst|txt|adoc)$")
#: chock's managed copies: installed policy text describes the patterns it judges.
MANAGED = re.compile(r"^\.agents/policies/|^\.chock/")
WAIVER = re.compile(r"chock:\s*allow\s+scan-hidden-content")
COMMENT_ONLY = re.compile(r"^\s*(<!--.*-->|\{/\*.*\*/\}|\[[^\]]*\]:\s*(#|<>)\s.*|#.*)\s*$")
WAIVABLE = frozenset({"commit", "push", "ci"})
ADVICE = (
    "Remove the hidden text or make it visible, and link to fixed URLs that carry nothing from the repository "
    "or the session. A person may keep a reviewed line with 'chock: allow scan-hidden-content' on it (or on a "
    "comment line just above) and commit from their own shell; in the agent only a waiver already committed "
    "in HEAD counts. This policy is in observe: it warns and records."
)


def kind_of(path: str) -> str | None:
    """How a path is read: markdown, markup, text, docx, or None when out of scope."""
    if MANAGED.search(path):
        return None
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".docx":
        return "docx"
    if suffix in MARKDOWN or RULE_FILES.search(path):
        return "markdown"
    if suffix in MARKUP:
        return "markup"
    if RULE_DIRS.search(path) or DOCS.search(path):
        return "text"
    return None


def digest(text: str) -> str:
    return hashlib.sha256(normalized(text).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _finding(path: str, line: int, rule: str, key: str, message: str) -> dict:
    tier = "would block" if rule in hidden_urls.BLOCKING else "would ask"
    return {"key": f"{rule}|{key}", "path": path, "line": line, "rule": rule, "message": f"[{tier}] {message}"}


def _url_findings(path: str, scan: str, lines: hidden_text.Lines, kind: str, tags: hidden_html.Collected) -> list[dict]:
    words = vocab()
    found: list[tuple[int, str, bool]] = []
    for offset, url in hidden_urls.text_urls(scan):
        found.append((lines.line(offset), url, False))
    if kind == "markdown":
        found += [(lines.line(at), dest, False) for at, dest, _ in hidden_text.definitions(scan)]
    found += tags.urls
    best: dict[tuple[int, str], hidden_urls.Verdict] = {}
    for line, url, embed in found:
        verdict = hidden_urls.judge(url, words, embed=embed)
        if verdict is None:
            continue
        slot = (line, verdict.host)
        held = best.get(slot)
        if held is None or (verdict.rule in hidden_urls.BLOCKING and held.rule not in hidden_urls.BLOCKING):
            best[slot] = verdict
    out = [
        _finding(path, line, v.rule, f"{v.host}|{v.shape}", f"URL to {v.host}: {v.reason}")
        for (line, _), v in sorted(best.items())
    ]
    for line, v in hidden_urls.runs([(line, url) for line, url, _ in found], words):
        out.append(_finding(path, line, v.rule, f"{v.host}|{v.shape}", f"URL dictionary on {v.host}: {v.reason}"))
    return out


def text_findings(path: str, text: str, kind: str) -> list[dict]:
    """Every hidden comment, hidden element, KaTeX trick, data-carrying URL and HTML data URI in one file."""
    scan = hidden_text.blank_code(text) if kind == "markdown" else text
    lines, scan_lines = hidden_text.Lines(scan), scan.split("\n")
    words = vocab()
    collected = hidden_html.collect(scan)
    out = _url_findings(path, scan, lines, kind, collected)
    bodies = [(at, body, "comment") for at, body in hidden_text.comments(scan)]
    if path.lower().endswith(".mdx"):
        bodies += [(at, body, "MDX comment") for at, body in hidden_text.comments(scan, mdx=True)]
    if kind == "markdown":
        bodies += [(at, t, "reference definition title") for at, _, t in hidden_text.definitions(scan) if t]
    for at, body, where in bodies:
        if reason := words.instruction(body):
            key = f"comment|{digest(body)}"
            out.append(_finding(path, lines.line(at), "hidden-comment", key, f"hidden {where}: {reason}"))
    for line, tag, reason, hidden in collected.hidden:
        key = f"{tag}|{reason}|{digest(hidden)}"
        out.append(_finding(path, line, "hidden-style", key, f"<{tag}> {reason}: {normalized(hidden)[:80]}"))
    if kind == "markdown":
        for at in hidden_text.katex(scan):
            key = f"katex|{digest(scan[at : at + KATEX_WINDOW])}"
            out.append(
                _finding(path, lines.line(at), "hidden-style", key, "KaTeX text coloured white, transparent or phantom")
            )
    for line in sorted({lines.line(at) for at in hidden_text.data_html(scan)} | set(collected.data_html)):
        key = digest(scan_lines[line - 1])
        out.append(_finding(path, line, "data-uri-html", key, "a data: URI carrying a whole HTML page"))
    return out


def docx_findings(path: str, payload: dict) -> list[dict]:
    data = hidden_docx.blob(
        str(payload.get("repo_root", ".")),
        str(payload.get("event", "")),
        path,
        baseline=payload.get("baseline") is True,
    )
    if data is None:
        return []
    try:
        runs = hidden_docx.hidden_runs(data)
    except hidden_docx.UnreadableError as exc:
        return [_finding(path, 1, "docx-unreadable", "docx", f"Word document not judged: {exc}")]
    return [
        _finding(
            path, 1, "docx-hidden", f"{part}|{reason}|{digest(text)}", f"{part}: {reason}: {normalized(text)[:80]}"
        )
        for part, reason, text in runs
    ]


def waived(finding: dict, lines: list[str]) -> bool:
    """A person's waiver on the finding's line, or on a comment-only line just above it."""
    number = finding["line"]
    if WAIVER.search(lines[number - 1]):
        return True
    return number > 1 and bool(COMMENT_ONLY.match(lines[number - 2])) and bool(WAIVER.search(lines[number - 2]))


def findings(payload: dict) -> list[dict]:
    """The findings of every written file in scope. The engine runs this again on the baseline text and
    judges only the keys the change holds more of."""
    writes = payload.get("writes")
    if not isinstance(writes, dict):
        raise TypeError("writes")
    waive = str(payload.get("event", "")) in WAIVABLE
    out: list[dict] = []
    for raw_path, text in sorted(writes.items()):
        path = str(raw_path).replace("\\", "/")
        kind = kind_of(path)
        if kind == "docx":
            out += docx_findings(path, payload)
        elif kind and isinstance(text, str) and len(text) > MAX_TEXT:
            message = f"{len(text)} characters, more than {MAX_TEXT}: not parsed, judged as changed"
            out.append(_finding(path, 1, "too-large", digest(text), message))
        elif kind and isinstance(text, str):
            lines = text.split("\n")
            out += [f for f in text_findings(path, text, kind) if not (waive and waived(f, lines))]
    return out


def main() -> int:
    try:
        found = findings(json.load(sys.stdin))
    except (ValueError, TypeError, AttributeError):
        print("scan-hidden-content: stdin is not the gate JSON; cannot judge", file=sys.stderr)
        return UNREADABLE
    if len(found) > MAX_FINDINGS:
        first = found[0]
        message = f"[would ask] {len(found)} findings, more than {MAX_FINDINGS}: judged as new"
        found = [
            {
                "key": "too-many",
                "path": first["path"],
                "line": first["line"],
                "rule": "too-many",
                "message": message,
                "new": True,
            }
        ]
    print(json.dumps({"findings": found}))
    if not found:
        return ALLOW
    print(
        "scan-hidden-content: this change adds text a reader cannot see, or a URL that carries data out:",
        file=sys.stderr,
    )
    for item in found[:SHOWN]:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    if OBSERVE:
        return WARN
    return BLOCK if any(f["rule"] in hidden_urls.BLOCKING for f in found) else ASK


if __name__ == "__main__":
    sys.exit(main())
