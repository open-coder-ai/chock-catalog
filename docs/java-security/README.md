# Java Security Rules

`java-security` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 28 total, 25 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: writing Java or Spring code, MyBatis mappers, JSP, Thymeleaf or FreeMarker templates, application.properties or application.yml. avoid: string-interpolated SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Eight rules, each with an allow|deny|ask verdict in .chock/security.json; a rule the file does not name denies.

## What it solves

A coding agent writing Java reaches for the construct that compiles and passes the test: `${col}` in a MyBatis ORDER BY, `th:utext` to stop a bio rendering as escaped text, a wildcard CORS origin with credentials to make the browser error go away, `include=*` so the dashboard sees every actuator endpoint, `parseClaimsJwt` one letter from the verifying call. Each is a vulnerability a reviewer would catch and a linter run at merge time reports after the agent has moved on. This policy refuses the eight at the commit, with the fix named in the refusal, and every rule carries the negative cases that keep it silent on the correct form -- `#{}`, `th:text`, a named origin, `setAllowedOriginPatterns`, `parseClaimsJws`.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> java-security: a Java construct a rule denies -- ${} in MyBatis SQL, unescaped template output, unsafe deserialization, a wildcard CORS origin with credentials, wildcard actuator exposure, an unverified JWT parse, a request-chosen file path, an ObjectInputStream over request bytes. Each rule's verdict is allow|deny|ask in .chock/security.json (absent = deny); waive one line with // chock: allow <rule-id>; choose per rule with skill configure-java-security.

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
