---
name: java-security
description: "trigger: writing Java or Spring code, MyBatis mappers, JSP, Thymeleaf or FreeMarker templates, application.properties or application.yml. avoid: string-interpolated SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Eight rules, each with an allow|deny|ask verdict in .chock/security.json; a rule the file does not name denies."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Java Security Rules

trigger: writing Java or Spring code, MyBatis mappers, JSP, Thymeleaf or FreeMarker templates, application.properties or application.yml. avoid: string-interpolated SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Eight rules, each with an allow|deny|ask verdict in .chock/security.json; a rule the file does not name denies.

```
on(commit|tool_use): block(script) script=java-security-gate.py
java-security: a Java construct a rule denies -- ${} in MyBatis SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Each rule's verdict is allow|deny|ask in .chock/security.json (absent = deny); waive one line with // chock: allow <rule-id>; choose per rule with skill configure-java-security.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
