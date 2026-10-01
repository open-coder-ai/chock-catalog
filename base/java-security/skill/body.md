## Guided setup

Asked to customize, configure, set up, review or change these rules -- "customize java
security" and anything meaning it -- open the guided page rather than asking the questions
as prose. Open it unasked, once, when Java is about to be written and no selection file
exists at either scope: every rule denies until someone chooses, and the page is a better
first meeting than the refusal. It is `setup.html`, in this skill's own directory beside this file and
`references/`. It is offline and writes nothing itself; deny is preselected for every rule,
and a verdict is chosen, never derived from a question about the stack. It asks once per pack --
java, crypto, spring, jakarta, persistence, templates, logging, build, android -- so a team
switches off a stack it does not run in one answer, and opens a pack's rules only when asked.

Where this client can publish an Artifact, publish that file as one, declaring
`capabilities: {db: {}}`, and let the person walk it in the panel. Their Submit writes the
result to the artifact's own store at `selection/current`; read that document back.
Everywhere else, open the page in a browser and take the result from their clipboard.

`result.selection` is the whole file and `result.wiring.scope` says where it goes. The file
sets each rule's verdict, so the person writes it from their own shell, never the agent:
protect-agent-config refuses an agent's write to either path.

- `repo`: `.chock/security.json` at the repository root, committed; where chock is
  installed there, `chock sync --repo .` afterwards.
- `user`: `~/.chock/security.json`, the floor for work outside a repository that carries its
  own. A repository carrying `.chock/security.json` governs itself: give no user-scope
  command, say so, and offer the repo-scope one for a pull request instead.

Show the person one row per rule, the whole resulting file and, where a selection exists,
the diff against it. Then give one command to paste into their own shell, and never run it:

    mkdir -p .chock && cat > .chock/security.json <<'EOF'
    <result.selection, as indented JSON>
    EOF

(`~/.chock` in both places for user scope.) Never put a pattern, severity or path in the file:
it carries verdicts only, and the gate refuses anything else at the next write. Reach for the
text walk -- `references/setup-contract.json`, one rule at a time, deny unless told
otherwise -- only where the page cannot be shown at all.

## Plan-time guidance

Before writing Java, call `chock_guidance` with your plan and the repo-relative paths you will
touch, where this client has that tool (`chock mcp`, served by chock, read-only, local). It
names the rules this repo's selection sets to deny or ask that the plan touches, each with its
constraint text. An empty answer is not a clearance: the gate still judges the code.

Wiring is not this skill's. Installed as a plugin, the hooks beside this file judge each
write and the turn's end; in a repository, `chock sync` adds the commit hook. Both read the
same selection file.
