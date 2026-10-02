#!/usr/bin/env python3
"""Report each injection pattern a write puts in an agent instruction file; the engine keeps the ones a change adds."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

# The rule tables ship beside this script. A missing copy raises here, and the runner treats an exit
# it did not ask for as undecided, which takes the declared action: never an allow. No bytecode cache
# is written: the gate is read_only in the repository it judges.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_scan import data_table  # noqa: E402 -- after the path and cache setup
from instr_blobs import blobs  # noqa: E402
from instr_judge import guardrails, judge  # noqa: E402
from instr_rules import ASK, BLOCK, Hit, Lexicon  # noqa: E402
from instr_text import Statement, lines_of, statements  # noqa: E402

ALLOW_EXIT, BLOCK_EXIT, UNREADABLE, ASK_EXIT = 0, 1, 2, 3
#: Past this many findings the document is one finding marked new: always judged, never compared.
MAX_FINDINGS = 10000
#: An instruction file longer than this is not read: a person looks at every change to it (keyed by its
#: whole text), so the gate stays inside the runner's 30-second budget, which the baseline run shares.
MAX_TEXT = 262144
SHOWN = 50
#: Agent instruction files, matched case-insensitively against the whole repository-relative path.
INSTRUCTION = re.compile(
    r"(?:^|/)(?:agents?\.md|agents\.override\.md|claude\.md|claude\.local\.md|gemini\.md|skill\.md|memory\.md"
    r"|\.cursorrules|\.windsurfrules|\.clinerules(?:/.+)?|\.roorules(?:-[^/]+)?|[^/]+\.(?:instructions|prompt|chatmode|agent)\.md"
    r"|\.github/copilot-instructions\.md|\.github/(?:instructions|prompts|agents|chatmodes)/.+"
    r"|\.cursor/rules/.+|\.windsurf/rules/.+|\.roo/rules(?:-[^/]+)?/.+|\.kiro/steering/.+|\.continue/(?:rules|prompts)/.+"
    r"|\.amazonq/rules/.+|\.augment/rules/.+|\.trae/rules/.+|\.junie/guidelines\.md|\.codex/prompts/.+"
    r"|\.gemini/commands/.+|\.claude/(?:commands|agents|skills|memory)/.+|\.agents/policies/index[^/]*\.md)$"
    r"|^memory/.+\.md$"
)
WAIVER = re.compile(r"chock:\s*allow\s+instruction-scan\b")
WAIVER_LINE = re.compile(r"\s*(?:<!--|#|//|/\*|;)?\s*chock:\s*allow\s+instruction-scan\b.*")
#: Where the text before the change lives, per event: the file on disk before a tool write, else HEAD.
FROM_DISK = frozenset({"tool_use", "pre-tool-use"})
FROM_HEAD = frozenset({"commit", "agent-commit", "stop", "push"})
GIT = shutil.which("git") or "git"
ADVICE = (
    "Instruction files are code an agent obeys: a person reviews every change to them. Keep rules as "
    "prohibitions a person wrote; never instruct an agent to send secrets, run downloaded or encoded code, "
    "skip review or hooks, or hide what it does. A person keeps a reviewed line by committing from their own "
    "shell -- with CHOCK_ALLOW=scan-instruction-files for an ask, or 'chock: allow instruction-scan' on the "
    "line for a refusal; an agent asks the person."
)


def canonical(path: str) -> str:
    """The path with backslashes as slashes and `//`, `.` and `..` segments folded."""
    return posixpath.normpath(path.replace("\\", "/"))


def judged(path: str) -> bool:
    return INSTRUCTION.search(canonical(path).casefold()) is not None


def file_hits(lex: Lexicon, text: str) -> list[Hit]:
    """Every rule that fires in one instruction file: statements, fake trust blocks and encoded blobs."""
    hits = judge(lex, statements(text))
    for blob in blobs(lines_of(text)):
        st = Statement(blob.first, blob.last, blob.run[:120], blob.run, code=True)
        hidden = blob.decoded is not None and (
            lex.p["exec_marker"].search(blob.decoded.casefold()) or judge(lex, statements(blob.decoded))
        )
        if hidden:
            hits.append(Hit("encoded-exec", BLOCK, "an encoded blob that decodes to a command or an instruction", st))
        else:
            hits.append(Hit("encoded-blob", ASK, "an encoded blob a person should decode and read", st))
    return hits


def _key(rule: str, norm: str) -> str:
    return f"{rule}|{hashlib.sha256(norm.encode('utf-8', 'replace')).hexdigest()[:16]}"


def _waived(hit: Hit, lines: list[str]) -> bool:
    span = lines[hit.statement.first - 1 : hit.statement.last]
    above = lines[hit.statement.first - 2] if hit.statement.first > 1 else ""
    return any(WAIVER.search(line) for line in span) or WAIVER_LINE.fullmatch(above) is not None


def before_text(payload: dict, path: str, text: str) -> str | None:
    """The file before the change, as the engine's baseline sees it, or None when there was none.

    Before a tool write that is the file on disk. The turn's end reaches the script as `tool_use` too,
    with the turn's writes already on disk, so a disk copy equal to the write means HEAD is the baseline
    (as the engine's own turn's-end baseline is). At commit it is HEAD. CI judges against a base the
    payload does not name, so there is none to read: removals go unjudged and every refusal-class
    finding counts as new.
    """
    event, root = str(payload.get("event", "")), Path(str(payload.get("repo_root", ".")))
    if event in FROM_DISK:
        try:
            disk = (root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            disk = None
        if disk != text:
            return disk
    elif event not in FROM_HEAD:
        return None
    if Path(path).is_absolute():
        return None
    shown = subprocess.run(  # noqa: S603 -- git itself, reading one blob; nothing from the write is run
        [GIT, "-C", str(root), "cat-file", "blob", f"HEAD:./{path}"], capture_output=True, check=False, timeout=10
    )
    return shown.stdout.decode("utf-8", "replace") if shown.returncode == 0 else None


def _finding(rule: str, label: str, path: str, st: Statement) -> dict:
    shown = " ".join(st.raw.split())[:120]
    return {"key": _key(rule, st.norm), "path": path, "line": st.first, "rule": rule, "message": f"{label}: {shown}"}


def removed_guardrails(lex: Lexicon, path: str, old: str, new_lines: int, text: str) -> list[dict]:
    """Guardrail statements the change deletes or rewords, when some topic they guard (tests, review, hooks,
    secrets...) is left with fewer guardrail statements than before: a weakening, not a rewording."""
    old_sts, new_sts = statements(old), statements(text)
    before, after = guardrails(lex, old_sts), guardrails(lex, new_sts)
    count_before = Counter(topic for topics in before.values() for topic in topics)
    count_after = Counter(topic for topics in after.values() for topic in topics)
    weakened = {topic for topic, n in count_before.items() if count_after[topic] < n}
    gone = Counter(old_sts[i].norm for i in before) - Counter(new_sts[i].norm for i in after)
    out = []
    for i in sorted(before):
        st = old_sts[i]
        if gone[st.norm] > 0 and before[i] & weakened:
            gone[st.norm] -= 1
            line = max(1, min(st.first, new_lines))
            out.append(_finding("guardrail-removed", "removes a guardrail statement", path, st._replace(first=line)))
    return out


def judge_file(lex: Lexicon, payload: dict, path: str, text: str) -> tuple[list[dict], bool]:
    """(findings, whether a block-class finding is new against the text before the change)."""
    waive = str(payload.get("event", "")) == "commit"
    if len(text) > MAX_TEXT:
        # Too long to read in the budget: refused, so padding a file cannot turn a refusal into an ask.
        if waive and WAIVER.search(text[: text.find("\n")] if "\n" in text else text):
            return [], False
        size = f"an instruction file over {MAX_TEXT} characters, too long to judge"
        oversize = _finding("oversize", size, path, Statement(1, 1, f"{len(text)} characters", text, code=False))
        return [oversize], not payload.get("baseline")
    lines = lines_of(text)
    hits = [h for h in file_hits(lex, text) if not (waive and _waived(h, lines))]
    found = [_finding(h.rule, h.label, path, h.statement) for h in hits]
    blocking = Counter(f["key"] for f, h in zip(found, hits, strict=True) if h.verdict == BLOCK)
    if payload.get("baseline"):
        return found, False
    old = before_text(payload, path, text)
    if old is not None and len(old) <= MAX_TEXT:
        found += removed_guardrails(lex, path, old, len(text.splitlines()), text)
        blocking -= Counter(_key(h.rule, h.statement.norm) for h in file_hits(lex, old) if h.verdict == BLOCK)
    return found, bool(blocking)


def findings(payload: dict) -> tuple[list[dict], bool]:
    """Every finding in the written instruction files, and whether any block-class one is new."""
    writes = payload.get("writes")
    if not isinstance(writes, dict) or not all(isinstance(payload.get(k, ""), str) for k in ("event", "repo_root")):
        raise TypeError("writes")
    judged_writes = {canonical(str(p)): t for p, t in writes.items() if judged(str(p))}
    if len(judged_writes) != sum(judged(str(p)) for p in writes) or not all(
        isinstance(t, str) for t in judged_writes.values()
    ):
        # Two spellings of one path would let the later text hide the earlier: cannot judge.
        raise TypeError("writes")
    if not judged_writes:
        return [], False
    lex = Lexicon()
    out: list[dict] = []
    block = False
    for path, text in sorted(judged_writes.items()):
        found, blocking = judge_file(lex, payload, path, text)
        out += found
        block = block or blocking
    return out, block


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        print("scan-instruction-files: stdin is not the gate JSON; cannot judge", file=sys.stderr)
        return UNREADABLE
    try:
        found, block = findings(payload)
    except (data_table.TableError, OSError, subprocess.SubprocessError) as exc:
        print(f"scan-instruction-files: cannot judge ({exc})", file=sys.stderr)
        return UNREADABLE
    except (TypeError, AttributeError):
        print("scan-instruction-files: stdin is not the gate JSON; cannot judge", file=sys.stderr)
        return UNREADABLE
    if len(found) > MAX_FINDINGS:
        first = found[0]
        found = [
            {
                "key": "too-many",
                "path": first["path"],
                "line": first["line"],
                "rule": "too-many",
                "message": f"{len(found)} findings, more than {MAX_FINDINGS}: judged as new",
                "new": True,
            }
        ]
    print(json.dumps({"findings": found}))
    if not found:
        return ALLOW_EXIT
    print(
        "scan-instruction-files: this change adds an injection pattern to an agent instruction file:", file=sys.stderr
    )
    for item in found[:SHOWN]:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    return BLOCK_EXIT if block else ASK_EXIT


if __name__ == "__main__":
    sys.exit(main())
