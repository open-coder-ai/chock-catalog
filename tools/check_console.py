#!/usr/bin/env python3
"""Fail if a quoted terminal transcript has drifted from what the tools actually print."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from chock.compile.emitters.advisory import template_message
from chock.gate.build import build_gate_json

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
BASE = ROOT / "base"

PROMPT = re.compile(r"^\$ (.+)$")
EXIT_MARKER = re.compile(r"^# exit (\d+)$")

PREFIX_WORDS = 6


def console_blocks(text: str) -> list[list[str]]:
    """Every ```console fence in `text`, as lists of lines."""
    return [block.strip("\n").splitlines() for block in re.findall(r"```console\n(.*?)```", text, re.S)]


def resolved_messages() -> dict[str, str]:
    """Each policy's block message, resolved the way the gate resolves it."""
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
    """Every `$ chock <sub>` in a transcript must name a real subcommand."""
    failures: list[str] = []
    for block in blocks:
        for line in block:
            match = PROMPT.match(line.strip())
            if not match:
                continue
            for part in match.group(1).split("&&"):
                words = part.split()
                if len(words) >= 2 and words[0] == "chock" and words[1] not in known:
                    failures.append(f"README shows `chock {words[1]}`, which is not a command.")
    return failures


def check_exit_markers(blocks: list[list[str]], messages: dict[str, str]) -> list[str]:
    """A block that quotes a refusal must not also claim it succeeded."""
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
