"""Commit-time front end: staged revisions in, refusals on stderr, exit code out."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from chock_security.decision import ASK, DENY, UNJUDGED, FileText, Finding
from chock_security.engine import evaluate
from chock_security.rules import registry
from chock_security.selection import SelectionError, load

EXIT_CLEAN = 0
EXIT_REFUSED = 1
EXIT_UNREADABLE_SELECTION = 2

#: An ask needs someone to ask. A hook has the developer's terminal, or it has nobody.
_TTY = "/dev/tty"

_NO_ONE_TO_ASK = (
    "chock-security: the finding(s) above are set to 'ask' and there is no terminal to ask "
    "(a non-interactive commit, a hook run from CI, or an agent committing on its own). "
    "Refusing rather than allowing: an ask never degrades to an allow.\n"
)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 -- reading the staged revision is this front end's job
        ["git", "-C", str(root), *args],  # noqa: S607 -- git resolves from PATH, as every hook does
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def staged(root: Path) -> list[FileText]:
    """Every staged path at the revision the commit would record, not at the working tree."""
    names = _git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMRT")
    files = []
    for name in names.splitlines():
        if not name.strip():
            continue
        try:
            files.append(FileText(name, _git(root, "show", f":{name}")))
        except subprocess.CalledProcessError:
            continue
    return files


def _confirmed(count: int) -> bool:
    """Put the ask to the developer's own terminal. No terminal is a refusal, never an allow."""
    try:
        with open(_TTY, "r+", encoding="utf-8") as tty:
            tty.write(f"chock-security: {count} finding(s) need a decision. Commit? [y/N] ")
            tty.flush()
            answer = tty.readline().strip().lower()
    except OSError:
        sys.stderr.write(_NO_ONE_TO_ASK)
        return False
    return answer in {"y", "yes"}


def verdict_of(findings: list[Finding]) -> int:
    """Deny wins over ask; an ask with nobody to answer it refuses too."""
    if any(f.verdict == DENY for f in findings):
        return EXIT_REFUSED
    asked = [f for f in findings if f.verdict == ASK]
    if asked and not _confirmed(len(asked)):
        return EXIT_REFUSED
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    """Refuse the commit when a rule denies, when an ask goes unanswered, or on a bad selection."""
    root = Path(argv[0]) if argv else Path.cwd()
    try:
        verdicts = load(root, registry())
    except SelectionError as exc:
        sys.stderr.write(f"chock-security: {exc}\n")
        return EXIT_UNREADABLE_SELECTION
    try:
        findings = evaluate(staged(root), verdicts)
    except Exception as exc:  # noqa: BLE001 -- any failure here refuses; it never falls through
        reason = UNJUDGED.format(reason=f"{type(exc).__name__}: {exc}")
        sys.stderr.write(reason + "\n")
        return EXIT_REFUSED
    for finding in findings:
        sys.stderr.write(finding.render() + "\n")
    return verdict_of(findings)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
