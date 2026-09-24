---
name: java-security
description: "trigger: writing Java or Kotlin -- Spring, Jakarta EE, Struts, Quarkus, Micronaut, Vert.x or Android -- SQL, JPA or MyBatis, Thymeleaf, JSP, JSF or FreeMarker templates, application.properties or .yml, web.xml, pom.xml or Gradle builds; \"customize java security\" opens this skill's guided page. avoid: injection (SQL, command, code, SpEL, LDAP, XPath, template), XXE, SSRF, unsafe deserialization, path traversal and zip slip, weak crypto and trust-all TLS, disabled Spring Security protections, exposed secrets and actuator data, known-exploited dependency versions, exported Android components. 72 rules in 9 packs (java, crypto, spring, jakarta, persistence, templates, logging, build, android), each rule or pack allow|deny|ask in .chock/security.json; absent = deny."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Java Security Rules

trigger: writing Java or Kotlin -- Spring, Jakarta EE, Struts, Quarkus, Micronaut, Vert.x or Android -- SQL, JPA or MyBatis, Thymeleaf, JSP, JSF or FreeMarker templates, application.properties or .yml, web.xml, pom.xml or Gradle builds; "customize java security" opens this skill's guided page. avoid: injection (SQL, command, code, SpEL, LDAP, XPath, template), XXE, SSRF, unsafe deserialization, path traversal and zip slip, weak crypto and trust-all TLS, disabled Spring Security protections, exposed secrets and actuator data, known-exploited dependency versions, exported Android components. 72 rules in 9 packs (java, crypto, spring, jakarta, persistence, templates, logging, build, android), each rule or pack allow|deny|ask in .chock/security.json; absent = deny.

```
on(commit|tool_use): block(script) script=java-security-gate.py
java-security: a construct one of its rules denies -- the refusal above names the rule, the pack it belongs to and the fix. Each rule's verdict is allow|deny|ask in .chock/security.json, per rule or per pack (java, crypto, spring, jakarta, persistence, templates, logging, build, android); absent = deny. Waive one line with // chock: allow <rule-id>; choose by asking to customize java security, which opens this skill's guided page.
```

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

`result.selection` is the whole file and `result.wiring.scope` says where it goes:

- `repo`: `.chock/security.json` at the repository root, committed; where chock is
  installed there, `chock sync --repo .` afterwards.
- `user`: `~/.chock/security.json`, the floor for work outside a repository that carries its
  own. A repository carrying `.chock/security.json` governs itself: refuse the user-scope
  write, say so, and offer to change the committed file in a pull request.

Show the person one row per rule before writing, and overwrite an existing selection only
after they have seen the diff. Never write a pattern, severity or path into the file: it
carries verdicts only, and the gate refuses anything else at the next write. Reach for the
text walk -- `references/setup-contract.json`, one rule at a time, deny unless told
otherwise -- only where the page cannot be shown at all.

Wiring is not this skill's. Installed as a plugin, the hooks beside this file judge each
write and the turn's end; in a repository, `chock sync` adds the commit hook. Both read the
same selection file.

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
