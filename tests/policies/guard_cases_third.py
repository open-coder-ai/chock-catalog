"""protect-agent-config: commands of the third review round, each refused or allowed."""

from __future__ import annotations

GIT_CONFIG_REFUSED = [
    "echo x > .git/config",
    "echo x >> .git/config",
    "sed -i s/a/b/ .git/config",
    "tee .git/config < a",
    "cp a .git/config",
    "mv a .git/config",
    "echo x > .git/hooks/pre-commit",
    "cat a | tee -a .git/config",
    "git config core.hooksPath x",
]

GIT_CONFIG_ALLOWED = [
    "cat .git/config",
    "git config user.name x",
    "git status",
    "echo x > .gitignore",
    "echo x > .git-blame-ignore-revs",
]

GIT_CLEAN_REFUSED = [
    "git clean -fdx -- .claude",
    "git clean -f .mcp.json",
    "git clean -fd .chock",
    "git clean -fdx",
    "git clean -fxd",
    "git clean -fdX",
    "git clean -f -x",
    "git clean -fd -e keep -x",
    "git -C . clean -fdx",
    "git clean -fd -- .claude/settings.json",
]

GIT_CLEAN_ALLOWED = [
    "git clean -n -fdx .cursor",
    "git clean -fd",
    "git clean -n",
    "git clean -fd src",
    "git clean -f src/build",
    "git clean -nd",
]

WINDOWS_REFUSED = [
    "xcopy .mcp.json out\\",
    "move .mcp.json out\\",
    "move a .mcp.json",
    "move /y a .claude\\settings.json",
    "xcopy a .cursor\\ /e",
    "xcopy a .cursor\\mcp.json",
    "robocopy a .cursor",
    "robocopy a .claude /MIR",
    "robocopy a .cursor mcp.json",
    "rename .mcp.json x",
    "ren .mcp.json x",
    'cmd /c "move a .mcp.json"',
    'cmd /c "xcopy a .cursor\\"',
    'cmd /c "robocopy a .claude /MIR"',
    'cmd /c "rename .mcp.json x"',
    "move .mcp.json x",
    "robocopy empty .cursor /PURGE",
    "xcopy /y a .mcp.json",
    "robocopy a .git\\hooks /E",
    "move a .git\\config",
    "cmd /c move a .mcp.json",
]

WINDOWS_ALLOWED = [
    "move a b",
    "xcopy a b /e",
    "robocopy a b /MIR",
    "rename a b",
    'cmd /c "move a b"',
    "robocopy src out /E",
    "robocopy .cursor out mcp.json",
]

MKTEMP_REFUSED = [
    "T=$(mktemp -d); echo x > $T/../.mcp.json",
    "T=$(mktemp -d); rm -rf $T/../.claude",
    "T=$(mktemp -d); cp a $T/../.mcp.json",
    "T=$(mktemp -d); cd $T/..; rm .mcp.json",
    "rm -f $LOG",
    "echo x > $OUT",
    'rm -rf "$BUILD_DIR"',
    "echo x > $LOG",
    "T=$(mktemp -d); echo x > $T/../../.mcp.json",
    "T=$(mktemp); rm $T/../.mcp.json",
    "echo x > $(mktemp)/../.mcp.json",
    "mv $(mktemp)/../.mcp.json out",
    "mv a $(mktemp)/../.mcp.json",
    "T=$(mktemp -d); mv a $T/../.cursor",
    "T=$(mktemp -d); cd $T; cd ..; rm .mcp.json",
    "T=$(mktemp -d); rm -rf $T/x/../../.claude",
]

MKTEMP_ALLOWED = [
    "tmp=$(mktemp); echo x > $tmp",
    "echo x > $(mktemp)",
    "T=$(mktemp -d); cp a $T/; rm -rf $T",
    "mv $(mktemp) out.txt",
    "T=$(mktemp -d); echo x > $T/out.txt",
    'T=$(mktemp -d); rm -rf "$T"',
    "tmp=$(mktemp $TMPDIR/x.XXXXXX); echo x > $tmp",
    "t=`mktemp`; echo x > $t",
    "t=$(mktemp -d) && cp -r a $t/b && rm -rf $t",
    'tmp=$(mktemp); cat a > "$tmp"',
    "tmp=$(mktemp); mv $tmp b.txt",
]

UNKNOWN_START_REFUSED = [
    "echo x > ${D}/mcp.json",
    "echo x > $D/mcp.json",
    "echo x > ${D}/settings.json",
    "echo x > $D/settings.json",
    "echo x > ${D}/.mcp.json",
    "echo x > $D/.mcp.json",
    "echo x > ${D}/.claude/settings.json",
    "echo x > $D/.claude/settings.json",
    "echo x > ${D}/CLAUDE.md",
    "echo x > $D/CLAUDE.md",
    "echo x > ${D}/AGENTS.md",
    "echo x > $D/AGENTS.md",
    "echo x > ${D}/hooks",
    "echo x > $D/hooks",
    "echo x > ${D}/bin",
    "echo x > $D/bin",
    "echo x > ${D}/state",
    "echo x > $D/state",
    "echo x > ${D}/chock",
    "echo x > $D/chock",
    "echo x > ${D}/pre-commit",
    "echo x > $D/pre-commit",
    "cd $UNKNOWN; echo x > mcp.json",
    "cd $UNKNOWN; echo x > hooks",
    "echo x > ${D}/.github/hooks/x",
    "echo x > ${D}/hooks/x",
    "echo x > ${D}/bin/x",
    "echo x > ${D}/compiled/x",
    "echo x > ${D}/state/x",
    "echo x > ${D}/implementations/x.py",
]

UNKNOWN_START_ALLOWED = [
    "D=; echo x > ${D}/mcp.json",
]

BASENAME_REFUSED = [
    "cp /srv/e/CLAUDE.md src/",
    "mv /srv/e/AGENTS.md docs/",
    "cp /srv/e/.mcp.json src/",
    "install /srv/e/GEMINI.md src/",
    "ln -s /srv/e/CLAUDE.md src/",
    "cp -t src /srv/e/CLAUDE.md",
    "cp /srv/e/CLAUDE.md docs",
    "mv /srv/e/.cursorrules src/",
    "cp /srv/e/settings.json .claude/",
    "cp /srv/e/mcp.json .cursor/",
    "cp a/AGENTS.md b/AGENTS.md src/",
    "cp --target-directory=src /srv/e/CLAUDE.md",
    "mv -t docs /srv/e/AGENTS.md",
    "cp /srv/e/.windsurfrules src/",
    "cp /srv/e/copilot-instructions.md src/",
    "cp /srv/e/.aider.conf.yml src/",
    "cp -r /srv/e/CLAUDE.md src",
]

BASENAME_ALLOWED = [
    "cp /srv/e/README.md src/",
    "mv /srv/e/notes.md docs/",
    "cp CLAUDE.md /srv/backup/",
    "cp AGENTS.md /srv/backup",
    "cp a src/",
]
