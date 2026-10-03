"""protect-agent-config v2: an instruction file under docs/ asks a person; everything else protected still blocks."""

from __future__ import annotations

NAMES = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".aider.conf.yml",
)

ASKED = [
    "echo x > docs/AGENTS.md",
    "echo x > docs/CLAUDE.md",
    "echo x > docs/GEMINI.md",
    "echo x > docs/copilot-instructions.md",
    "echo x > docs/.cursorrules",
    "echo x > docs/.windsurfrules",
    "echo x > docs/.aider.conf.yml",
    "echo x > docs/AGENTS.md.txt",
    "echo x > DOCS/agents.md",
    "echo x > docs/sub/AGENTS.md",
    "echo x > site/docs/AGENTS.md",
    "echo x > ./docs/./AGENTS.md",
    "echo x > docs//AGENTS.md",
    "sed -i s/a/b/ docs/AGENTS.md",
    "echo x | tee docs/CLAUDE.md",
    "rm docs/AGENTS.md",
    "mv docs/AGENTS.md docs/OLD.md",
    "cp x docs/GEMINI.md",
    "bash -c 'echo x > docs/AGENTS.md'",
    "echo x > docs/AGENTS.md && echo y > docs/CLAUDE.md",
]

# Not the docs/ carve-out: the root file, a path that leaves docs/, a folder that is protected whole, or a look-alike folder.
# A command is asked only when it spells the path `docs/...`: a `cd docs`, a variable or Windows backslashes are read as the file anywhere.
BLOCKED = [
    "cd docs && echo x > AGENTS.md",
    "D=docs; echo x > $D/AGENTS.md",
    "echo x > docs\\AGENTS.md",
    "echo x > AGENTS.md",
    "echo x > src/AGENTS.md",
    "echo x > docs/../AGENTS.md",
    "cd docs && echo x > ../AGENTS.md",
    "echo x > docs/.claude/settings.json",
    "echo x > docs/.cursor/rules/a.mdc",
    "echo x > .claude/docs/AGENTS.md",
    "echo x > .agents/docs/CLAUDE.md",
    "echo x > .chock/docs/AGENTS.md",
    "echo x > docs/.github/copilot-instructions.md",
    "echo x > mydocs/AGENTS.md",
    "echo x > docs.old/AGENTS.md",
    "echo x > documents/AGENTS.md",
    "echo x > docs/AGENTS.md; echo y > AGENTS.md",
    "echo x | tee docs/AGENTS.md AGENTS.md",
    "echo x > docs/AGENTS.md; echo y > .claude/settings.json",
    "echo x > docs/.mcp.json",
]

ALLOWED = [
    "cat docs/AGENTS.md",
    "grep -n x docs/CLAUDE.md",
    "echo x > docs/guide.md",
    "echo x > docs/agents.txt",
    "echo AGENTS.md > docs/index.md",
]
