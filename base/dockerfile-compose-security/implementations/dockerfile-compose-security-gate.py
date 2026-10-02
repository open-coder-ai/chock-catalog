#!/usr/bin/env python3
"""Report Dockerfile and compose findings in a write; the engine keeps only the ones a change adds."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path, PurePosixPath

# The rules ship beside this script. A missing or broken copy raises here, and the runner treats an
# exit it did not ask for as undecided (the gate's declared action), never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dkscan import dockerfile, dockerrules, stages
from dkscan.compose import compose_hits
from dkscan.context import Repo, agent_commit
from dkscan.rules import DENY, RULES, Ctx, Hit

DOCKERFILE = re.compile(
    r"^(?:(?:docker|container)file(?:[._-][\w.-]+)?|[\w.-]+\.(?:docker|container)file)$", re.IGNORECASE
)
NOT_DOCKERFILE = re.compile(
    r"\.(?:md|rst|txt|py|json|ya?ml|sh|ignore|dockerignore|html|j2|tpl|bak|orig)$", re.IGNORECASE
)
COMPOSE = re.compile(r"^(?:docker-)?compose(?:[._-][\w.-]+)?\.ya?ml$", re.IGNORECASE)
WAIVER = re.compile(r"chock:\s*allow\s+([\w-]+)")
COMMENT = re.compile(r"^\s*#")
EXIT_BLOCK, EXIT_ASK = 1, 3


def kind_of(path: str) -> str | None:
    name = PurePosixPath(path).name
    if COMPOSE.match(name):
        return "compose"
    if DOCKERFILE.match(name) and not NOT_DOCKERFILE.search(name):
        return "dockerfile"
    return None


def has_dockerignore(path: str, payload: dict, repo: Repo) -> bool:
    """A .dockerignore next to the Dockerfile, at the repository root, or named for the Dockerfile."""
    parent = PurePosixPath(path).parent
    names = {str(parent / ".dockerignore"), ".dockerignore", f"{path}.dockerignore"}
    if any(name.removeprefix("./") in payload.get("writes", {}) for name in names):
        return True
    return any((repo.root / name).is_file() for name in names)


def dockerfile_hits(path: str, text: str, payload: dict, repo: Repo) -> list[Hit]:
    instrs = dockerfile.parse(text)
    ctx = Ctx(
        ignored=has_dockerignore(path, payload, repo),
        fetch_exec_elsewhere=repo.fetch_exec_reads(path),
        pins_elsewhere=repo.pins_reads(),
        node_tls_elsewhere=repo.node_tls_reads(path),
    )
    hits = stages.walk(instrs, ctx)
    for instr in instrs:
        hits.extend(dockerrules.instruction_hits(instr, ctx))
    return hits


def marks_by_line(text: str, kind: str) -> dict[int, list[str]]:
    """Where a `chock: allow <rule>` may sit for a finding on each line: the line itself and the comment above it.

    In a Dockerfile that is every physical line of the instruction, plus the comment line directly above it.
    """
    lines = text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    marks: dict[int, list[str]] = {}
    if kind == "dockerfile":
        for instr in dockerfile.parse(text):
            for number in instr.lines:
                marks[number] = [instr.above, *instr.raw]
        return marks
    for number, line in enumerate(lines, 1):
        above = lines[number - 2] if number > 1 and COMMENT.match(lines[number - 2]) else ""
        marks[number] = [line, above]
    return marks


def waivable(event: str, repo: Repo) -> bool:
    """A waiver counts only at commit, and never for a commit the engine would mark as an agent's."""
    return event == "commit" and not agent_commit(repo.root)


def findings(payload: dict) -> list[dict]:
    """Every finding in the written Dockerfiles and compose files, keyed by rule, path and the normalized construct."""
    repo = Repo(Path(str(payload.get("repo_root") or ".")))
    waive = waivable(str(payload.get("event", "")), repo)
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        kind = kind_of(norm)
        if kind is None or not isinstance(text, str):
            continue
        if kind == "compose":
            hits = compose_hits(text, Ctx(pins_elsewhere=repo.pins_reads()))
        else:
            hits = dockerfile_hits(norm, text, payload, repo)
        marks = marks_by_line(text, kind) if waive else {}
        for hit in sorted(set(hits), key=lambda h: (h.line, h.rule, h.detail)):
            if any(hit.rule in WAIVER.findall(mark) for mark in marks.get(hit.line, ())):
                continue
            rule = RULES[hit.rule]
            found.append(
                {
                    "key": f"{hit.rule}|{' '.join(hit.detail.split())[:400]}",
                    "path": norm,
                    "line": hit.line,
                    "rule": hit.rule,
                    "message": f"{hit.rule} ({rule.cwe or 'unreadable'}; {rule.refs}): {hit.why}. Fix: {rule.fix}",
                }
            )
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("dockerfile-compose-security: stdin is not the gate JSON", file=sys.stderr)
        return 2
    found = findings(payload)
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print(
        "dockerfile-compose-security: a Dockerfile or compose change weakens the container's isolation or supply chain:",
        file=sys.stderr,
    )
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "A person may keep a reviewed finding with '# chock: allow <rule-id>' on the line or the comment line above "
        "it, committing from their own shell; in the agent only a line already committed in HEAD counts.",
        file=sys.stderr,
    )
    return EXIT_BLOCK if any(RULES[item["rule"]].tier == DENY for item in found) else EXIT_ASK


if __name__ == "__main__":
    sys.exit(main())
