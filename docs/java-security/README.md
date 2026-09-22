# Java Security Rules

`java-security` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: block`) |
| **Mechanism** | commit-time guard script `java-security-pre-commit.py` |
| **Reaches** | `enforced-at-commit` — the script exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ambient-rule` |
| **Eval cases** | 28 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: writing Java or Spring code, MyBatis mappers, JSP, Thymeleaf or FreeMarker templates, application.properties or application.yml. avoid: string-interpolated SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Eight rules, each with an allow|deny|ask verdict in .chock/security.json; a rule the file does not name denies.

## What it solves

A coding agent writing Java reaches for the construct that compiles and passes the test: `${col}` in a MyBatis ORDER BY, `th:utext` to stop a bio rendering as escaped text, a wildcard CORS origin with credentials to make the browser error go away, `include=*` so the dashboard sees every actuator endpoint, `parseClaimsJwt` one letter from the verifying call. Each is a vulnerability a reviewer would catch and a linter run at merge time reports after the agent has moved on. This policy refuses the eight at the commit, with the fix named in the refusal, and every rule carries the negative cases that keep it silent on the correct form -- `#{}`, `th:text`, a named origin, `setAllowedOriginPatterns`, `parseClaimsJws`.

## How it works

A guard script, `implementations/java-security-pre-commit.py`, run by the git hook at every commit with no arguments. It reads the staged revision of each file from git and exits non-zero to refuse the commit.

The rule text ships alongside, so an agent reading its context knows the constraint before it stages the change rather than only after being refused:

```text
never(write): mybatis ${} in SQL | th:utext|<%=|escapeXml="false"|?no_esc|<#noescape> | jackson defaultTyping | XStream w/o allowTypes | CORS "*" + allowCredentials(true) | actuator exposure.include=* | parseClaimsJwt|parseUnsecuredClaims|Algorithm.none|unverified JWT.decode | request data -> file path | ObjectInputStream
on(fire): .chock/security.json -> allow|deny|ask per rule; absent|no-terminal ask = deny; waive a line: // chock: allow <rule-id>; choose: skill configure-java-security
```

## Which primitive it becomes

A **commit-time guard script**. `recompile` registers `implementations/java-security-pre-commit.py` under `.git/hooks/pre-commit.d/`, and the hook runs it with no arguments at every commit. The script reads the staged revision from git itself and exits non-zero to refuse; the rule text compiles to `ambient-rule` beside it, so the agent knows the constraint before the commit is refused.

## Installing it

```bash
chock add java-security
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/java-security  <your-repo>/.agents/policies/java-security
cd <your-repo> && chock sync --repo .
```

## Customising it

Verdicts, never rules. `.chock/security.json` sets each rule to `allow`, `deny` or `ask` (the `configure-java-security` skill walks the page that writes it), and a rule the file does not name denies, so an upgrade's new rule runs until someone speaks for it. A single line is waived in place with `// chock: allow <rule-id>`, where the diff shows it. What a rule matches lives in `implementations/chock_security/data/java.json` (API names, template tokens) and `rules/*.py`; a pattern in the selection file is refused, because a rule definable in JSON is a program in disguise. Adding a rule is a version bump of this one policy, not a ninth folder.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals java-security
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/java-security/`](../../base/java-security/) · [all policies](../README.md)
