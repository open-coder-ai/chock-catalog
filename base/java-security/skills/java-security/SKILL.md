---
name: java-security
description: "trigger: writing Java or Kotlin (Spring, Jakarta EE, Quarkus, Android), SQL/JPA/MyBatis, templates, application.properties/.yml, web.xml, pom.xml, Gradle; \"customize java security\" opens the guided page. avoid: injection, XXE, SSRF, unsafe deserialization, path traversal, weak crypto, trust-all TLS, Spring Security off, exposed secrets, known-exploited deps, SpotBugs/Sonar/PMD/Checkstyle findings. 129 rules, 16 packs, each allow|deny|ask in .chock/security.json; absent = deny (quality: allow)."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Java Security Rules

trigger: writing Java or Kotlin (Spring, Jakarta EE, Quarkus, Android), SQL/JPA/MyBatis, templates, application.properties/.yml, web.xml, pom.xml, Gradle; "customize java security" opens the guided page. avoid: injection, XXE, SSRF, unsafe deserialization, path traversal, weak crypto, trust-all TLS, Spring Security off, exposed secrets, known-exploited deps, SpotBugs/Sonar/PMD/Checkstyle findings. 129 rules, 16 packs, each allow|deny|ask in .chock/security.json; absent = deny (quality: allow).

```
on(commit|tool_use): block(script) script=java-security-gate.py
java-security: a construct one of its rules denies -- the refusal above names the rule, the pack it belongs to and the fix. Each rule's verdict is allow|deny|ask in .chock/security.json, per rule or per pack (java, crypto, spring, jakarta, persistence, templates, logging, build, android, bugs, concurrency, resources, exceptions, performance, style, testing); absent = deny for a security pack, allow for a quality pack (bugs through testing). Only what the change adds is refused: a violation on lines the change leaves alone never blocks it. Only a human reviewer waives a line, with // chock: allow <rule-id>, never the agent: in the agent a waiver counts once a human has committed it. Choose verdicts by asking to customize java security, which opens this skill's guided page.
```

## Guided setup

Asked to customize, configure, set up, review or change these rules -- "customize java
security" and anything meaning it -- open the guided page rather than asking the questions
as prose. Open it unasked, once, when Java is about to be written and no selection file
exists at either scope: every security rule denies until someone chooses (a quality pack's
rules allow), and the page is a better first meeting than the refusal. It is `setup.html`, in
this skill's own directory beside this file and `references/`. It is offline and writes
nothing itself; each rule's pack default is preselected (deny for a security pack, allow for
a quality pack), and a verdict is chosen, never derived from a question about the stack. It
asks once per pack -- java, crypto, spring, jakarta, persistence, templates, logging, build,
android, then the quality packs -- so a team switches off a stack it does not run in one
answer, and opens a pack's rules only when asked.

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
text walk -- `references/setup-contract.json`, one rule at a time, its pack's `default` unless told
otherwise -- only where the page cannot be shown at all.

## Plan-time guidance

Before writing Java, call `chock_guidance` with your plan and the repo-relative paths you will
touch, where this client has that tool (`chock mcp`, served by chock, read-only, local). It
names the rules this repo's selection sets to deny or ask that the plan touches, each with its
constraint text. An empty answer is not a clearance: the gate still judges the code.

Wiring is not this skill's. Installed as a plugin, the hooks beside this file judge each
write and the turn's end; in a repository, `chock sync` adds the commit hook. Both read the
same selection file.

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
