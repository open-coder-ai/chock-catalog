#!/usr/bin/env python3
"""Fail if a quoted terminal transcript has drifted from what the tools actually print.

`check_readme.py` guards the README's *numbers*; `gen_policy_docs.py` guards the docs pages.
Nothing guarded the ```console blocks -- and that is the class that broke twice. Once when the
`protect-main-branch` block message read "(main/master)" while the gate it described blocked
`main|master`, and once when a transcript labelled "captured by running these commands" had
gone stale.

Both were quoted output, and quoted output is the most persuasive thing in a README precisely
because a reader cannot verify it. A wrong number invites a correction; a wrong transcript
teaches an adopter that the tool says something it does not, and they find out at the moment
it blocks their commit.

Replaying the transcript in full would need a scratch repo, the network and a catalog clone.
This instead checks the part that actually drifts, offline: every line of quoted output that
claims to be a gate's block message must equal the message that gate really resolves to, and
every `$ chock ...` command must be one the CLI has.

Usage:  python tools/check_console.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from chock.compile.emitters.advisory import template_message
from chock.gate.build import build_gate_json

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
BASE = ROOT / "base"

#: A `$ ` prompt line, and the `# exit N` convention the transcripts use to record status.
PROMPT = re.compile(r"^\$ (.+)$")
EXIT_MARKER = re.compile(r"^# exit (\d+)$")

#: How much of a resolved message must appear verbatim before a line is treated as a quotation
#: of it. Long enough that ordinary prose cannot collide; short enough to survive the tail of
#: the message changing, which is exactly where the substituted params live and where the
#: "(main/master)" defect was.
PREFIX_WORDS = 6


def console_blocks(text: str) -> list[list[str]]:
    """Every ```console fence in `text`, as lists of lines."""
    return [block.strip("\n").splitlines() for block in re.findall(r"```console\n(.*?)```", text, re.S)]


def resolved_messages() -> dict[str, str]:
    """Each policy's block message, resolved the way the gate resolves it.

    `build_gate_json` applies config defaults, so this is the message an adopter is actually
    shown -- not the manifest's literal, which may still contain `{refs}`.
    """
    messages: dict[str, str] = {}
    for policy_dir in sorted(p for p in BASE.iterdir() if p.is_dir()):
        spec = build_gate_json(policy_dir, ROOT)
        if not spec or not spec.get("message"):
            continue
        resolved = " ".join(template_message(str(spec["message"]), spec.get("params") or {}).split())
        messages[policy_dir.name] = resolved
    return messages


def cli_commands() -> set[str]:
    from chock.cli import COMMANDS

    return set(COMMANDS)


def check_quoted_messages(blocks: list[list[str]], messages: dict[str, str]) -> list[str]:
    """A quoted block message must match the gate's resolved message exactly."""
    failures: list[str] = []
    prefixes = {pid: " ".join(msg.split()[:PREFIX_WORDS]) for pid, msg in messages.items()}

    for block in blocks:
        for line in block:
            stripped = line.strip()
            if not stripped or PROMPT.match(stripped) or EXIT_MARKER.match(stripped):
                continue
            for policy_id, prefix in prefixes.items():
                if not stripped.startswith(prefix):
                    continue
                if stripped != messages[policy_id]:
                    failures.append(
                        f"README quotes a {policy_id} message that the gate does not produce.\n"
                        f"      quoted: {stripped}\n"
                        f"    resolves: {messages[policy_id]}"
                    )
    return failures


def check_commands(blocks: list[list[str]], known: set[str]) -> list[str]:
    """Every `$ chock <sub>` in a transcript must name a real subcommand.

    A transcript is a promise that these commands were run. One that does not exist could not
    have been, so the transcript is fabricated whether or not anyone meant it to be.
    """
    failures: list[str] = []
    for block in blocks:
        for line in block:
            match = PROMPT.match(line.strip())
            if not match:
                continue
            # Transcripts chain with `&&`; check each invocation, not just the first.
            for part in match.group(1).split("&&"):
                words = part.split()
                if len(words) >= 2 and words[0] == "chock" and words[1] not in known:
                    failures.append(f"README shows `chock {words[1]}`, which is not a command.")
    return failures


def check_exit_markers(blocks: list[list[str]], messages: dict[str, str]) -> list[str]:
    """A block that quotes a refusal must not also claim it succeeded.

    Cheap, but it catches the copy-paste error that turns a demonstration of enforcement into
    a demonstration of the opposite -- the single most damaging thing this README could say.
    """
    failures: list[str] = []
    for block in blocks:
        text = "\n".join(block)
        exits = [int(m.group(1)) for line in block if (m := EXIT_MARKER.match(line.strip()))]
        blocked = any(msg in text for msg in messages.values())
        if blocked and exits and all(code == 0 for code in exits):
            failures.append(f"A block quoting a refusal records `# exit 0`:\n{text}")
    return failures


def main() -> int:
    if not README.exists():
        print("No README.md found.", file=sys.stderr)
        return 2

    blocks = console_blocks(README.read_text(encoding="utf-8"))
    if not blocks:
        # Not an error, but worth saying: this checker silently passing because it found
        # nothing to check is indistinguishable from it working.
        print("No ```console blocks found in README.md; nothing to verify.")
        return 0

    messages = resolved_messages()
    failures = (
        check_quoted_messages(blocks, messages)
        + check_commands(blocks, cli_commands())
        + check_exit_markers(blocks, messages)
    )

    if failures:
        print(f"Console transcript drift ({len(failures)} problem(s)):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print("\nRe-run the documented commands and paste the real output.", file=sys.stderr)
        return 1

    print(f"Console transcripts match: {len(blocks)} block(s), {len(messages)} gate message(s) checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
