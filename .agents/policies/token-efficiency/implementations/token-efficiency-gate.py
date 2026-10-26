"""Warn on a third identical Read of a file, or a command retried past the retry cap."""

from __future__ import annotations

import importlib
import json
import os
import re
import sys

READ_REPEAT = 3
RETRY_CAP = 3
EDITS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
PATH_KEYS = ("file_path", "filePath", "path", "notebook_path", "target_file", "TargetFile")
FIELD_CAP = 300
REDACTED = "[redacted]"
#: The session log's redaction (the scan-secrets shapes chock's log_redact replaces), so a command holding one is
#: compared as stored. Kept in step with chock's runtime; a log that stored the command unredacted is matched too.
SECRET = re.compile(
    r"""(?i)((AKIA|ASIA)[0-9A-Z]{16}|gh[oprsu]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|xox[bpas]-[0-9A-Za-z-]{10,}|(sk|rk)_live_[0-9A-Za-z]{16,}|sk-proj-[0-9A-Za-z_-]{20,}|sk-ant-[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_-]{35}|npm_[0-9A-Za-z]{36}|SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}|eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*|-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|api[_-]?key\s*=\s*["'][A-Za-z0-9_\-]{20,}["']|secret[_-]?key\s*=\s*["'][A-Za-z0-9_\-]{20,}["']|auth[_-]?token\s*=\s*["'][A-Za-z0-9_\-]{20,}["']|password\s*=\s*["'][^"'\s]{12,}["']|(api|secret|auth)[_-]?(key|token)\s*[=:]\s*[A-Za-z0-9_\-]{20,}|password\s*[=:]\s*[^\s"'${}]{12,})"""
)


def load_log(root: str):
    """The vendored session reader, or None when this install has none."""
    sys.path.insert(0, os.path.join(root, ".chock", "bin"))
    try:
        return importlib.import_module("chock_session")
    except ImportError:
        return None


def masked_command(command: str) -> str:
    """First line with the value of every NAME=value word masked."""
    words = []
    for word in command.splitlines()[0].split(" "):
        name, eq, _ = word.partition("=")
        words.append(name + eq + "***" if eq and name.isidentifier() else word)
    return " ".join(words)


def logged_command(command: str) -> str:
    """The command as the session log stores it: first line, NAME=value words masked, secrets redacted, capped."""
    return SECRET.sub(REDACTED, masked_command(command))[:FIELD_CAP]


def logged_forms(command: str) -> list[str]:
    """The stored form, and the form a log written before redaction holds when it differs."""
    return list(dict.fromkeys([logged_command(command), masked_command(command)[:FIELD_CAP]]))


def reads_since_edit(log, records, path: str) -> int:
    """Reads of `path` logged since it was last edited."""
    reads = 0
    for record in records:
        if (record.get("input") or {}).get("path") != path:
            continue
        if record.get("tool") in EDITS:
            reads = 0
        elif record.get("tool") == "Read" and record.get("phase") == log.PRE and record.get("outcome") != "blocked":
            reads += 1
    return reads


def failures_since_success(log, records, command: str) -> int:
    """Failed runs of `command` since it last succeeded."""
    failures = 0
    for record in log.matching(records, tool="Bash", phase=log.POST, command=command):
        failures = failures + 1 if record.get("outcome") == log.ERROR else 0
    return failures


def judge(log, payload: dict) -> str:
    """The warning for this call, or an empty string."""
    records = log.prior(payload.get("session") or {})
    tool_input = payload.get("input") or {}
    if payload.get("tool") == "Read":
        path = next((tool_input[k] for k in PATH_KEYS if isinstance(tool_input.get(k), str) and tool_input[k]), "")
        if path and reads_since_edit(log, records, path) >= READ_REPEAT - 1:
            return (
                f"{path} was already read {READ_REPEAT - 1} times since it last changed; reuse what you have, "
                "read only the range you need, or ignore this if you are paging through a large file."
            )
    command = tool_input.get("command")
    if payload.get("tool") == "Bash" and isinstance(command, str) and len(command.strip().splitlines()) == 1:
        failed = max(failures_since_success(log, records, form) for form in logged_forms(command))
        if failed >= RETRY_CAP:
            return f"this exact command has failed {failed} times (retry cap {RETRY_CAP}); read the error and change approach."
    return ""


def main() -> int:
    payload = json.load(sys.stdin)
    log = load_log(str(payload.get("repo_root", ".")))
    message = judge(log, payload) if log else ""
    if message:
        sys.stderr.write(message)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
