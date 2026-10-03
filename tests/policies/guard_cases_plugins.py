"""protect-agent-config: a plugin root's hooks folder is protected where a `.claude-plugin/` folder makes the root, and nowhere else."""

from __future__ import annotations

# The repository the tests build: `mods/p` and `mods/q` are plugin roots (q has no hooks folder yet), `app/.claude-plugin` is a file.
ROOTS = ("mods/p/.claude-plugin/plugin.json", "mods/q/.claude-plugin/plugin.json")
FILES = {
    "app/.claude-plugin": "not a folder\n",
    "src/hooks/useThing.ts": "export {}\n",
    "mods/p/hooks/hooks.json": "{}\n",
}

REFUSED = [
    "echo x > mods/p/hooks/hooks.json",
    "echo x > mods/p/hooks/register.ts",
    "echo x > mods/p/hooks/register.tsx",
    "echo x > mods/p/hooks/new/deep/mod.ts",
    "echo x > mods/q/hooks/hooks.json",
    "echo x > mods/p/Hooks/register.tsx",
    "echo x > MODS/P/HOOKS/register.ts",
    "echo x > ./mods/p/../p/hooks/a.ts",
    "echo x > mods//p/./hooks/a.ts",
    "echo x > mods\\p\\hooks\\a.ts",
    "cd mods/p && echo x > hooks/hooks.json",
    "cd mods/p/hooks && echo x > a.ts",
    "D=mods/p; echo x > $D/hooks/hooks.json",
    "echo x > mods/p/ho*/hooks.json",
    "echo x > mods/*/hooks/hooks.json",
    "rm mods/p/hooks/hooks.json",
    "rm -rf mods/p/hooks",
    "cp evil.json mods/p/hooks/hooks.json",
    "mv a.ts mods/p/hooks/a.ts",
    "tee mods/p/hooks/hooks.json",
    "sed -i s/a/b/ mods/p/hooks/hooks.json",
    "bash -c 'echo x > mods/p/hooks/a.ts'",
    "echo x > mods/p/.claude-plugin/plugin.json",
    "rm -rf mods/p/.claude-plugin",
    "echo x > ./.claude-plugin/plugin.json",
]
ALLOWED = [
    "echo x > src/hooks/useThing.ts",
    "echo x > src/hooks/useOther.tsx",
    "echo x > hooks/a.ts",
    "echo x > mods/p/src/hooks/a.ts",
    "echo x > mods/p/commands/a.md",
    "echo x > mods/other/hooks/a.ts",
    "echo x > app/hooks/a.ts",
    "echo x > docs/plugins.md",
    "echo x > docs/hooks/guide.md",
    "echo x > nowhere/hooks/a.ts",
    "cat mods/p/hooks/hooks.json",
    "ls mods/p/hooks",
    "grep -rn useThing src/hooks",
    "echo x > mods/p/hooks.md",
    "echo x > mods/p/hooksx/a.ts",
    "echo x > mods/p/xhooks/a.ts",
]
