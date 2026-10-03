"""protect-agent-config: commands of the eighth review round, each refused or allowed."""

from __future__ import annotations

CLUSTERS = [
    "bash -co pipefail",
    "bash -oc pipefail",
    "bash -Oc extglob",
    "bash -cO extglob",
    "bash -c -oe pipefail",
    "bash -c -ox pipefail",
    "bash -c +o noglob",
    "bash -coO pipefail extglob",
    "sh -c -",
    "dash -c -",
    "env bash -co pipefail",
]

B1_REFUSED = [f"{pre} '{script}'" for pre in CLUSTERS for script in ("rm AGENTS.md", "echo x > .mcp.json")]

B1_ALLOWED = [
    "bash -co pipefail 'ls src'",
    "bash -oc pipefail 'ls src'",
    "bash -Oc extglob 'echo hi'",
    "sh -c - 'ls'",
    "dash -c - 'echo ok'",
    "bash -c -oe pipefail 'echo hi'",
    "bash -co pipefail 'cat AGENTS.md'",
    "bash -o pipefail -c 'ls src'",
]

B2_REFUSED = [
    "eval \"echo x > \\$'\\\\x2e'mcp.json\"",
    "bash -c \"echo x > \\$'\\\\x2e'mcp.json\"",
    "env sh -c \"echo x > \\$'\\\\x2e'mcp.json\"",
    "xargs -0 sh -c \"echo x > \\$'\\\\x2e'mcp.json\"",
    "bash -lc \"echo x > \\$'\\\\x2e'mcp.json\"",
    "eval \"echo x > \\$'\\\\056'mcp.json\"",
    "eval \"echo x > \\$'\\\\u002e'mcp.json\"",
    "eval \"rm \\$'\\\\x41'GENTS.md\"",
    'eval "eval \\"echo x > \\\\\\$\'\\\\\\\\x2e\'mcp.json\\""',
    'x="echo x > \\$\'\\\\x2e\'mcp.json"; sh -c "$x"',
    "echo \"echo x > \\$'\\\\x2e'mcp.json\" | sh",
]

B2_ALLOWED = [
    "eval \"echo \\$'\\\\x41'BD\"",
    "eval \"echo x > \\$'\\\\x2e'notes\"",
    'bash -c "echo \\$HOME"',
    'eval "echo A\\\\\\\\GENTS"',
]

S1_REFUSED = [
    "git fetch --upload-pack='rm AGENTS.md' .",
    "git fetch --upl='rm AGENTS.md' .",
    "git fetch --upload-pack 'rm AGENTS.md' .",
    "git clone --upload-pack='rm AGENTS.md' . d",
    "git clone -u 'rm AGENTS.md' . d",
    "git clone -u'rm AGENTS.md' . d",
    "git clone --config core.fsmonitor='rm AGENTS.md' . d",
    "git clone -c core.fsmonitor='rm AGENTS.md' . d",
    "git push --receive-pack='rm AGENTS.md' .",
    "git push --exec='rm AGENTS.md' .",
    "git ls-remote --upload-pack='rm AGENTS.md' .",
    "git pull --upload-pack='rm AGENTS.md' .",
    "git archive --remote=. --exec='rm AGENTS.md' HEAD",
]

S1_ALLOWED = [
    "git fetch origin",
    "git fetch --upload-pack=git-upload-pack origin",
    "git clone https://example.com/r.git d",
    "git clone -c core.autocrlf=false https://example.com/r.git d",
    "git clone -u git-upload-pack . d",
    "git clone --template=tpl . d",
    "git push origin main",
    "git push --exec=git-receive-pack origin",
    "git pull --ff-only",
    "git ls-remote origin",
]

S2_REFUSED = [
    "git -c protocol.ext.allow=always ls-remote 'ext::sh -c \"rm AGENTS.md\"'",
    "GIT_ALLOW_PROTOCOL=ext git ls-remote 'ext::sh -c \"rm AGENTS.md\"'",
    "git clone 'ext::sh -c \"echo x > .mcp.json\"' d",
]

S2_ALLOWED = ["git clone ext::foo d", "git ls-remote 'ext::sh -c \"echo hi\"'"]

S3_REFUSED = [
    "git archive -o AGENTS.md HEAD",
    "git archive --output=AGENTS.md HEAD",
    "git archive --out AGENTS.md HEAD",
    "git archive -oAGENTS.md HEAD",
    "git bundle create AGENTS.md HEAD",
    "git grep -O'rm AGENTS.md' x",
    "git grep -nO'rm AGENTS.md' x",
    "git grep --open-files-in-pager='rm AGENTS.md' x",
]

S3_ALLOWED = [
    "git archive -o out.tar HEAD",
    "git archive HEAD -- AGENTS.md",
    "git bundle create out.bundle HEAD",
    "git bundle verify out.bundle",
    "git bundle create",
    "git grep -O x",
    "git grep -O less foo src",
    "git grep -n AGENTS.md",
]

# block-destructive-commands and block-no-verify read the same clusters through the shared reader.
DESTRUCTIVE_REFUSED = [f"{pre} 'rm -rf /'" for pre in CLUSTERS]
DESTRUCTIVE_ALLOWED = ["bash -co pipefail 'ls src'", "sh -c - 'echo hi'"]
NO_VERIFY_REFUSED = [f"{pre} 'git commit --no-verify -m x'" for pre in CLUSTERS]
