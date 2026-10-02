#!/usr/bin/env python3
"""Report hidden text and data-carrying URLs in Markdown, HTML, SVG, XML and Word files; the engine keeps what a change adds."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path, PurePosixPath

# The scanners ship beside this script. A missing or broken copy raises here, and the runner treats an
# exit it did not ask for as undecided, which takes the declared action. No bytecode cache is written:
# the gate is read_only in the repository it judges.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from hiddenscan import links as hidden_urls  # noqa: E402
from hiddenscan import markdown as hidden_text  # noqa: E402
from hiddenscan import markup as hidden_html  # noqa: E402
from hiddenscan import spans  # noqa: E402 -- after the path and cache setup
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
#: The engine gives the change run and the baseline run 30 seconds together. Past this many seconds in one
#: run, the files not yet read are reported, marked new, so one slow file cannot cost every finding.
DEADLINE = 10.0
#: Would block once promoted: a secret-bearing beacon, a URL dictionary, and a file the run had no time to
#: read (it may hold either, so running out of time never softens the verdict).
#: Elements whose content this Python's HTML parser reads as raw text (the list varies by release).
RAW_TEXT = re.compile(rf"<(?:{'|'.join(hidden_html.RAW_TEXT_ELEMENTS)})(?![A-Za-z0-9-])", re.IGNORECASE)
BLOCKING = hidden_urls.BLOCKING | {"not-judged"}
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
#: A waiver is a line holding nothing but the marker, as a comment, just above the finding: a marker
#: inside the hidden text or the URL itself is part of what is judged, never a waiver.
WAIVER = re.compile(
    r"(?:<!--\s*{m}\s*-->|\{{/\*\s*{m}\s*\*/\}}|\[//\]:\s*#\s*\(\s*{m}\s*\)|#\s*{m})".format(
        m=r"chock:\s*allow\s+scan-hidden-content"
    )
)
WAIVABLE = frozenset({"commit", "push", "ci"})
ADVICE = (
    "Remove the hidden text or make it visible, and link to fixed URLs that carry nothing from the repository "
    "or the session. A person may keep a reviewed line with a comment line just above it holding only "
    "'chock: allow scan-hidden-content', committed from their own shell; in the agent only a waiver already "
    "committed in HEAD counts. This policy is in observe: it warns and records."
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
    tier = "would block" if rule in BLOCKING else "would ask"
    return {"key": f"{rule}|{key}", "path": path, "line": line, "rule": rule, "message": f"[{tier}] {message}"}


def _urls(scan: str, lines: hidden_text.Lines, kind: str, tags: hidden_html.Collected) -> dict[tuple[int, str], int]:
    """Each distinct (line, URL as a client reads it) with how it is fetched (links.LINK, IMAGE or TAG)."""
    image, link, tag = hidden_urls.IMAGE, hidden_urls.LINK, hidden_urls.TAG
    found = [(lines.line(at), url, image if is_image else link) for at, url, is_image in hidden_urls.text_urls(scan)]
    if kind == "markdown":
        images = hidden_text.image_labels(scan)
        found += [
            (lines.line(at), dest, image if label in images else link)
            for at, label, dest, _ in hidden_text.definitions(scan)
        ]
    found += [(line, url, tag if embed else link) for line, url, embed in tags.urls]
    out: dict[tuple[int, str], int] = {}
    for line, raw, load in found:
        slot = (line, hidden_urls.clean(raw))
        out[slot] = max(out.get(slot, link), load)
    return out


def _url_findings(path: str, urls: dict[tuple[int, str], int]) -> list[dict]:
    words, out = vocab(), []
    for (line, url), load in sorted(urls.items()):
        if hidden_text.DATA_HTML.match(url):
            out.append(_finding(path, line, "data-uri-html", digest(url), "a data: URI carrying a whole HTML page"))
        elif verdict := hidden_urls.judge(url, words, load=load):
            key = f"{verdict.host}|{verdict.shape}"
            out.append(_finding(path, line, verdict.rule, key, f"URL to {verdict.host}: {verdict.reason}"))
    for line, v in hidden_urls.runs(list(urls), words):
        out.append(_finding(path, line, v.rule, f"{v.host}|{v.shape}", f"URL dictionary on {v.host}: {v.reason}"))
    return out


def text_findings(path: str, text: str, kind: str) -> list[dict]:
    """Every hidden comment, hidden element, KaTeX trick, data-carrying URL and HTML data URI in one file.

    In Markdown, URLs are read with code blanked (code is shown, not fetched), and tags and comments from the
    text with only the '<' of code removed, so code inside a comment or an HTML block still counts."""
    scan = spans.blank_code(text) if kind == "markdown" else text
    tags = spans.tag_view(text, scan) if kind == "markdown" else text
    views = [(tags, tags, False)]
    if kind == "markdown":  # what a renderer may read two ways is read both ways: each reading's findings count
        views = [
            (view, html, False)
            for view in dict.fromkeys([tags, spans.escaped_view(tags)])
            for html in dict.fromkeys([view, spans.closed_view(text, view)])
        ]
        flat = spans.flat_view(tags)
        if flat != tags or RAW_TEXT.search(tags):  # otherwise the flat reading is the first one
            views += [(tags, html, True) for html in dict.fromkeys([flat, spans.closed_view(text, flat)])]
    out: dict[tuple, list[dict]] = {}
    for reading in views:  # per finding, as many as the reading that found the most: counts stay counts
        found: dict[tuple, list[dict]] = {}
        for f in _view_findings(path, scan, kind, reading):
            found.setdefault((f["line"], f["rule"], f["key"]), []).append(f)
        for slot, same in found.items():
            if len(same) > len(out.get(slot, [])):
                out[slot] = same
    return [f for same in out.values() for f in same]


def _view_findings(path: str, scan: str, kind: str, reading: tuple[str, str, bool]) -> list[dict]:
    tags, html, flat = reading  # comments are read in tags, elements in html
    lines, scan_lines = hidden_text.Lines(scan), scan.split("\n")
    words = vocab()
    collected = hidden_html.collect(html, xml=PurePosixPath(path).suffix.lower() in (".svg", ".xml"), flat=flat)
    out = _url_findings(path, _urls(scan, lines, kind, collected))
    bodies = [(at, body, "comment") for at, body in hidden_text.comments(tags)]
    if path.lower().endswith(".mdx"):
        bodies += [(at, body, "MDX comment") for at, body in hidden_text.comments(tags, mdx=True)]
    if kind == "markdown":
        bodies += [(at, t, "reference definition title") for at, _, _, t in hidden_text.definitions(scan) if t]
    for at, body, where in bodies:
        if reason := words.instruction(body):
            key = f"comment|{digest(body)}"
            out.append(_finding(path, lines.line(at), "hidden-comment", key, f"hidden {where}: {reason}"))
    for line, tag, reason, shown, key in collected.hidden:
        out.append(
            _finding(path, line, "hidden-style", f"{tag}|{reason}|{key}", f"<{tag}> {reason}: {normalized(shown)}")
        )
    katex_lines = {lines.line(at) for at in hidden_text.katex(scan)} if kind == "markdown" else set()
    for line in sorted(katex_lines):
        key = f"katex|{digest(scan_lines[line - 1])}"
        out.append(_finding(path, line, "hidden-style", key, "KaTeX text coloured white, transparent or phantom"))
    judged = {f["line"] for f in out if f["rule"] == "data-uri-html"}
    for line in sorted(({lines.line(at) for at in hidden_text.data_html(scan)} | set(collected.data_html)) - judged):
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


def waived(finding: dict, lines: list[str], event: str, seen: dict[int, bool]) -> bool:
    """A person's waiver: a marker-only comment line just above the finding, each line read once. CI does
    not honour one on a would-block finding, since a pull request's author may be anyone."""
    number = finding["line"]
    if number <= 1 or (event == "ci" and finding["rule"] in BLOCKING):
        return False
    if number not in seen:
        seen[number] = bool(WAIVER.fullmatch(lines[number - 2].strip()))
    return seen[number]


def findings(payload: dict) -> list[dict]:
    """The findings of every written file in scope. The engine runs this again on the baseline text and
    judges only the keys the change holds more of."""
    writes = payload.get("writes")
    if not isinstance(writes, dict):
        raise TypeError("writes")
    event = str(payload.get("event", ""))
    out: list[dict] = []
    started = time.monotonic()
    # Smallest first, so a slow large file cannot keep the deadline from the small ones.
    for raw_path, text in sorted(writes.items(), key=lambda item: (len(str(item[1])), str(item[0]))):
        path = str(raw_path).replace("\\", "/")
        kind = kind_of(path)
        if kind and time.monotonic() - started > DEADLINE:
            message = f"not read: the gate's {DEADLINE:.0f}-second share of its budget ran out first"
            out.append({**_finding(path, 1, "not-judged", "late", message), "new": True})
        elif kind == "docx":
            out += docx_findings(path, payload)
        elif kind and isinstance(text, str) and len(text) > MAX_TEXT:
            message = f"{len(text)} characters, more than {MAX_TEXT}: not parsed, judged as changed"
            raw = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]
            out.append(_finding(path, 1, "too-large", raw, message))
        elif kind and isinstance(text, str):
            lines, seen = text.split("\n"), {}
            out += [
                f for f in text_findings(path, text, kind) if not (event in WAIVABLE and waived(f, lines, event, seen))
            ]
    return out


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("writes"), dict):
        print("scan-hidden-content: stdin is not the gate JSON; cannot judge", file=sys.stderr)
        return UNREADABLE
    found = findings(payload)
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
    return BLOCK if any(f["rule"] in BLOCKING for f in found) else ASK


if __name__ == "__main__":
    sys.exit(main())
