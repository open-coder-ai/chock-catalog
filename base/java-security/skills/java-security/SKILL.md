---
name: java-security
description: "trigger: writing Java or Spring code, MyBatis mappers, JSP, Thymeleaf or FreeMarker templates, application.properties or application.yml. avoid: string-interpolated SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Eight rules, each with an allow|deny|ask verdict in .chock/security.json; a rule the file does not name denies."
metadata:
  chock.artifact: rule
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Java Security Rules

trigger: writing Java or Spring code, MyBatis mappers, JSP, Thymeleaf or FreeMarker templates, application.properties or application.yml. avoid: string-interpolated SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Eight rules, each with an allow|deny|ask verdict in .chock/security.json; a rule the file does not name denies.

```
never(write): mybatis ${} in SQL | th:utext|<%=|escapeXml="false"|?no_esc|<#noescape> | jackson defaultTyping | XStream w/o allowTypes | CORS "*" + allowCredentials(true) | actuator exposure.include=* | parseClaimsJwt|parseUnsecuredClaims|Algorithm.none|unverified JWT.decode | request data -> file path | ObjectInputStream
on(fire): .chock/security.json -> allow|deny|ask per rule; absent|no-terminal ask = deny; waive a line: // chock: allow <rule-id>; choose: skill configure-java-security
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
