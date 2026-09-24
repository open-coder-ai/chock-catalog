# Java Security Rules

`java-security` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 84 total, 76 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: writing Java or Kotlin -- Spring, Jakarta EE, Struts, Quarkus, Micronaut, Vert.x or Android -- SQL, JPA or MyBatis, Thymeleaf, JSP, JSF or FreeMarker templates, application.properties or .yml, web.xml, pom.xml or Gradle builds; "customize java security" opens this skill's guided page. avoid: injection (SQL, command, code, SpEL, LDAP, XPath, template), XXE, SSRF, unsafe deserialization, path traversal and zip slip, weak crypto and trust-all TLS, disabled Spring Security protections, exposed secrets and actuator data, known-exploited dependency versions, exported Android components. 72 rules in 9 packs (java, crypto, spring, jakarta, persistence, templates, logging, build, android), each rule or pack allow|deny|ask in .chock/security.json; absent = deny.

## What it solves

A coding agent writing Java reaches for the construct that compiles and passes the test: `${col}` in a MyBatis ORDER BY, a SQL string glued together with `+`, `csrf().disable()` to get a POST working, `th:utext` so a bio renders, a trust-all TrustManager to get past a certificate error, `include=*` so the dashboard sees every actuator endpoint, a Log4j version from a tutorial. Each is a vulnerability a reviewer would catch and a scanner run at merge time reports after the agent has moved on. This policy refuses them as they are written and at the commit, with the fix named in the refusal, across 72 rules in nine packs -- core Java, crypto, Spring, Jakarta EE and the other frameworks, persistence, templates, logging, the build, and Android -- and every rule carries the negative cases that keep it silent on the correct form: `#{}` and bind parameters, `th:text`, `parseClaimsJws`, AES-GCM, a named CORS origin.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> java-security: a construct one of its rules denies -- the refusal above names the rule, the pack it belongs to and the fix. Each rule's verdict is allow|deny|ask in .chock/security.json, per rule or per pack (java, crypto, spring, jakarta, persistence, templates, logging, build, android); absent = deny. Waive one line with // chock: allow <rule-id>; choose by asking to customize java security, which opens this skill's guided page.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/java-security/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

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

Verdicts, never rules. `.chock/security.json` sets each pack, or each rule inside it, to `allow`, `deny` or `ask` -- a team with no Android app or no Spring switches that pack off in one line -- and asking to customize java security opens the guided page in this policy's own skill, which asks once per pack and writes the file. A rule the file does not name denies, so an upgrade's new rule runs until someone speaks for it. A single line is waived in place with `// chock: allow <rule-id>`, where the diff shows it. What a rule matches lives in `implementations/chock_security/data/<pack>.json` (API names, tokens, config keys, vulnerable version ranges) and `rules/<pack>/*.py`; a pattern in the selection file is refused, because a rule definable in JSON is a program in disguise. Adding a rule is a version bump of this one policy, never another folder.

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
