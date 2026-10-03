"""protect-agent-config v2: whole agent directories, case-insensitive segments, and the commands that must stay open."""

from __future__ import annotations

# One file of no particular name in each agent directory: the whole folder is protected, not a list of its files.
ROOTS = (
    ".claude",
    ".cursor",
    ".codex",
    ".gemini",
    ".windsurf",
    ".agents",
    ".chock",
    ".junie",
    ".devin",
    ".grok",
    ".tabnine",
    ".github/copilot",
)
LEAF = "notes/anything.md"

REFUSED = [
    "echo x > .claude/commands/a.md",
    "echo x > .claude/agents/a.md",
    "echo x > .cursor/rules/a.mdc",
    "touch .cursor/rules/a.mdc",
    "mv .cursor/rules/a.mdc .cursor/rules/b.mdc",
    "cd .cursor/rules && echo x > a.mdc",
    "D=.cursor; echo x > $D/rules/a.mdc",
    "echo x > .devin/other.json",
    "echo x > .codex/other.toml",
    "echo x > .gemini/other.json",
    "echo x > .windsurf/rules/chock.md",
    "echo x > .agents/skills/a/SKILL.md",
    "echo x > .chock/notes.md",
    "echo x > .github/copilot-setup-steps.yml",
    "echo x > .github/copilot/prompts/a.md",
    "echo x > .junie/guidelines.md",
    "echo x > .grok/GROK.md",
    "echo x > .tabnine/agent/notes.md",
    "rm .claude/commands/a.md",
    "rm -rf .claude",
    "cp a.md .claude/commands/a.md",
    "tee .cursor/rules/a.mdc",
    "sed -i s/a/b/ .claude/agents/a.md",
]

# The same writes spelled so a case-insensitive filesystem reaches the same folder.
CASED = [
    "echo x > .CLAUDE/settings.json",
    "echo x > .Claude/Commands/a.md",
    "echo x > .CURSOR/RULES/A.MDC",
    "echo x > .Codex/Prompts/a.md",
    "echo x > .AGENTS/skills/a/SKILL.md",
    "echo x > .GitHub/Copilot/a.md",
    "echo x > .GITHUB/COPILOT-INSTRUCTIONS.MD",
    "echo x > .Chock/Notes.md",
    "rm -rf .CLAUDE",
    "cd .Claude && echo x > a.md",
    "cp a .CuRsOr/rules/a.mdc",
]

# Relative paths, `..`, doubled and dotted separators, Windows separators, a redirection after a pipe or a wrapper.
RESPELLED = [
    "echo x > src/../.claude/commands/a.md",
    "cd src && echo x > ../.claude/commands/a.md",
    "echo x > ./.claude/commands/a.md",
    "echo x > .claude//commands/a.md",
    "echo x > .claude/./commands/a.md",
    "echo x > .claude/x/../commands/a.md",
    "echo x > .claude\\commands\\a.md",
    "echo x > .CLAUDE\\Commands\\a.md",
    "copy a.md .cursor\\rules\\a.mdc",
    "echo x | tee .cursor/rules/a.mdc",
    "echo x | sudo tee .claude/commands/a.md",
    "bash -c 'echo x > .claude/commands/a.md'",
    'sh -c "printf x >> .cursor/rules/a.mdc"',
    "env FOO=1 sh -c 'echo x > .codex/prompts/a.md'",
    "echo x >| .claude/commands/a.md",
    "echo x &> .claude/commands/a.md",
    "echo x 2> .claude/commands/err.log",
    "cat <<EOF > .claude/commands/a.md\nx\nEOF",
    "echo x >> .gemini/commands/a.toml",
    "python3 -c \"open('.claude/commands/a.md','w').write('x')\"",
]

# What stays open: reads, the folders themselves, look-alike names, and the CI files another policy owns.
ALLOWED = [
    "cat .claude/commands/a.md",
    "ls -la .claude",
    "ls .cursor/rules",
    "grep -rn TODO .claude/commands",
    "git diff .claude",
    "git log -p -- .cursor/rules/a.mdc",
    "mkdir .cursor",
    "mkdir -p .cursor/rules",
    "echo x > claude/commands/a.md",
    "echo x > docs/claude-notes.md",
    "echo x > src/claudes/a.md",
    "echo x > .claudex/a.md",
    "echo x > .cursors/a.md",
    "echo x > .agent/a.md",
    "echo x > .agentsx/a.md",
    "echo x > .githubx/copilot/a.md",
    "echo x > .github/workflows/ci.yml",
    "echo x > .github/ISSUE_TEMPLATE/a.md",
    "echo x > .github/dependabot.yml",
    "echo x > .vscode/settings.json",
    "echo x > .vscode/launch.json",
    "echo .claude/commands/a.md > notes.txt",
    "echo 'rm -rf .claude' > /var/tmp/note",
    "echo x > out.txt",
]
