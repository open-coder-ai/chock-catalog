#!/usr/bin/env python3
"""Ask when an agent's write or commit touches CI, hook or bot config; the path alone decides, and a person's commit is not judged."""

from __future__ import annotations

import json
import re
import sys

ASK, UNREADABLE = 3, 2
# The events judged: the write before it lands (and the turn's end), and a commit the engine reads as an agent's.
JUDGED = ("tool_use", "agent-commit")
# The manifest's gate message, which the engine does not print for a script gate; a test fails on drift.
MESSAGE = (
    "This path is CI, release, hook or dependency-bot configuration: the checks that review an agent's own work. "
    "An agent's change to it needs a person's decision. Say which file should change, what and why, and let the "
    "person approve the edit or make it from their own shell. Where a person cannot be asked, the write is refused: "
    "propose the change instead. At the turn's end this is a reminder that such a file is still changed and "
    "uncommitted. A person's own commit is not judged."
)
PATH = re.compile(
    r'(?i)(?:^|[/\\])(?:(?:\.github[. ]*(?::[^/\\:]*){0,2}[/\\](?:\.?[/\\])*(?:workflows|actions|workflow-templates)|\.gitlab(?:-ci)?|\.circleci|\.azure-pipelines|\.buildkite|\.husky|\.githooks|\.lefthook(?:-local)?|\.woodpecker|\.semaphore|\.tekton)[. ]*(?::[^/\\:]*){0,2}(?:[/\\]|$)|(?:\.github[. ]*(?::[^/\\:]*){0,2}[/\\](?:\.?[/\\])*dependabot\.ya?ml|CODEOWNERS|[^/\\]*\.gitlab-ci\.ya?ml|azure-pipelines[^/\\]*\.ya?ml|bitbucket-pipelines\.ya?ml|buildkite\.ya?ml|\.drone\.(?:ya?ml|jsonnet|star)|cloudbuild[^/\\]*\.(?:ya?ml|json)|renovate\.json5?|\.renovaterc(?:\.json5?)?|\.pre-commit-config\.ya?ml|\.?lefthook(?:-local)?\.(?:ya?ml|json|toml)|\.travis\.ya?ml|action\.ya?ml|\.woodpecker\.ya?ml|\.?appveyor\.ya?ml|\.cirrus\.ya?ml|buildspec[^/\\]*\.ya?ml|bitrise\.ya?ml|codemagic\.ya?ml)[. ]*(?::[^/\\:]*){0,2}$|Jenkinsfile[^/\\]*(?<!\.md)(?<!\.txt)(?<!\.rst)(?<!\.adoc)(?<!\.py)(?<!\.java)(?<!\.kt)(?<!\.js)(?<!\.ts)(?<!\.go)$)'
)


def printable(path: str) -> str:
    """A path as one safe line: a control character in a file name never reaches the terminal."""
    return "".join(char if char.isprintable() else "?" for char in path)[:200]


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        event, writes = payload.get("event"), payload.get("writes", {})
        paths = sorted(path for path in writes if PATH.search(path))
    except (ValueError, AttributeError, TypeError):
        print("protect-ci-workflows: stdin is not the gate JSON", file=sys.stderr)
        return UNREADABLE
    if event not in JUDGED or not paths:
        return 0
    for path in paths:
        print(f"{printable(path)}: CI, hook or bot configuration", file=sys.stderr)
    print(MESSAGE, file=sys.stderr)
    return ASK


if __name__ == "__main__":
    sys.exit(main())
