<div align="center">

<img src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/logo.svg" alt="chock-catalog: the policy catalog for chock -- policies you can adopt, graded by what they actually enforce. The mark is a stack of policy cards, the top one carrying the node that marks an enforcing policy." width="110">

<h1>chock-catalog</h1>

<p><strong>Application security for the code your AI agents write -- checked as they write it, at commit and in CI.</strong></p>

<p>
<img alt="48 policies" src="https://img.shields.io/badge/policies-48-D9B45C?labelColor=0D1626">
<img alt="1,182 eval cases" src="https://img.shields.io/badge/eval_cases-1%2C182-D9B45C?labelColor=0D1626">
<a href="docs/coverage.md"><img alt="OWASP Agentic Top 10: 10/10 risks have a policy" src="https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10-D9B45C?labelColor=0D1626"></a>
<img alt="28 enforced" src="https://img.shields.io/badge/enforced-28-brightgreen?labelColor=0D1626">
<img alt="20 advisory" src="https://img.shields.io/badge/advisory-20-orange?labelColor=0D1626">
<img alt="agents" src="https://img.shields.io/badge/agents-15-8957e5?labelColor=0D1626">
<br>
<a href="https://github.com/open-coder-ai/chock-catalog/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/open-coder-ai/chock-catalog/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://scorecard.dev/viewer/?uri=github.com/open-coder-ai/chock-catalog"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/open-coder-ai/chock-catalog/badge"></a>
<img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-lightgrey">
<a href="CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
</p>

<p>
<a href="#why-application-security">Why</a> ·
<a href="#quick-start">Quick start</a> ·
<a href="#what-it-stops">What it stops</a> ·
<a href="#a-normal-day-by-role">By role</a> ·
<a href="#security-coverage-by-area">By area</a> ·
<a href="#the-tiers-guardrails-not-guarantees">Tiers</a> ·
<a href="#how-it-works">How it works</a> ·
<a href="#contributing">Contributing</a> ·
<a href="https://github.com/open-coder-ai/chock">the framework →</a>
</p>

<img src="https://raw.githubusercontent.com/open-coder-ai/chock/main/docs/assets/demo.gif" width="760" alt="Terminal: 5 security guards adopted from the catalog; a hard-coded AWS key, an MCP server at @latest, a wildcard IAM grant, model output piped into os.system and a Trojan Source bidi override are each refused at commit; the fixed file commits cleanly.">

</div>

## Why application security

Coding agents already ask before they run a shell command. What they don't check is the
code they write -- SQL injection in a Spring repository, unsafe deserialization, a wildcard
IAM grant, an MCP server pinned to `@latest`, a stripped `aria-label`, a secret written into
agent memory. Chock checks that code at the agent's own hook where the client has one, and
again at commit and in CI, with rules for Java and Kotlin, agent code, cloud IAM, supply
chain, accessibility and the OWASP Agentic Top 10.

Agents, left alone, write code a security reviewer would have caught:

| The agent writes… | Refused by |
| :--- | :--- |
| SQL built by concatenation or MyBatis `${}`, unsafe deserialization, XXE, trust-all TLS, disabled Spring Security | `java-security` |
| agent code that runs model output on the host (`allow_dangerous_code=True`, `use_docker: False`), switches tool approvals off, or turns TLS verification off | `agentic-code-security` |
| bare `eval`/`exec`, `shell=True`, `pickle` loads, `yaml.load` without `SafeLoader` | `block-unsafe-code-execution` |
| `"Action": "*"` in IAM, `AdministratorAccess`, GCP `roles/owner` | `block-wildcard-iam` |
| a dependency you have not allowlisted, an MCP server at `@latest`, an Action at a movable tag | `verify-dependency-exists`, `block-unpinned-agent-components`, `verify-mcp-allowlist`, `pin-github-actions` |
| a "cleanup" that empties an `alt` or drops an `aria-label` | `no-a11y-regression` |
| a secret, a pasted diff or a 60-line code block into its own memory | `guard-memory-writes` |
| bidi override controls (Trojan Source) or Unicode tag characters that hide instructions | `block-invisible-unicode` |
| deleted assertions or new skips, to turn CI green | `protect-test-integrity`, `block-test-skips` |

<details>
<summary><strong>Also included</strong> -- the shell, git and agent-config guards</summary>

Agents ship their own prompts for these. Chock adds a policy committed to the repo, the same
for every agent and every developer -- a gate at commit, or a guard before the tool runs.

| The agent… | Refused by |
| :--- | :--- |
| hard-codes an API key | `scan-secrets` |
| runs `rm -rf`, `git push --force`, `terraform destroy` | `block-destructive-commands`, `rtk-dangerous-actions-blocker` |
| skips every hook with `--no-verify` | `block-no-verify` |
| edits its own guardrail config or CI workflows | `protect-agent-config`, `protect-ci-workflows` |
| grants itself an allow-everything tool list | `block-wildcard-agent-permissions` |
| spawns a sub-agent with `--dangerously-skip-permissions` | `block-unguarded-agent-spawn` |
| POSTs repo data to an unknown host, or pipes `curl` into `sh` | `block-unapproved-egress`, `block-curl-pipe-sh` |

</details>

A rule in a prompt is forgotten when the context fills; a hook that exits non-zero is not.
**A rule an agent reads is advice. A hook that exits non-zero is a control.** Every policy
here says which of the two it is. Guards are stdlib Python or shell -- deterministic, no LLM
calls, no network access at enforcement time, and short enough to review.

---

## Quick start

The whole install is three commands, in a repo of your own:

```bash
pip install chock

git init -q demo && cd demo
chock init .
chock add scan-secrets
chock sync --repo .
```

The next commit containing a credential exits non-zero instead of landing -- the refusal,
word for word, is in [It actually blocks the commit](#it-actually-blocks-the-commit).

Add the rest by area: `chock add java-security`, `chock add agentic-code-security`,
`chock add block-destructive-commands`, … then `chock sync --repo .` once.

---

## What it stops

| Area | What gets refused | Policies | Strongest tier |
| :--- | :--- | ---: | :--- |
| [Secure code: Java / Kotlin](#secure-code-java--kotlin) | 129 rules in 16 packs: injection, XXE, SSRF, deserialization, weak crypto, Spring misconfig, known-exploited versions | 1 | enforced-at-commit |
| [Secure code: agent code & cloud privilege](#secure-code-agent-code--cloud-privilege) | 29 rules in 10 packs for agent frameworks, plus `eval`/`shell=True`/`pickle` and wildcard IAM | 3 | enforced-at-commit |
| [Supply chain](#supply-chain) | dependencies off your allowlist, Actions not pinned to a commit SHA, agent components at `@latest` | 3 | enforced-at-commit |
| [OWASP Top 10 for Agentic Applications](#owasp-top-10-for-agentic-applications) | a policy for each of ASI01–ASI10; 7 have a slice enforced at commit | 10 | advisory + enforced slices |
| [Accessibility (ADA / Section 508 / WCAG)](#accessibility-ada--section-508--wcag) | a change that retracts an accessible name an element already had | 1 | enforced-at-commit |
| [Memory guardrails](#memory-guardrails) | secrets, pasted git history and oversized code blocks written into agent memory | 2 | enforced-at-commit |
| [Prompt injection](#prompt-injection) | Trojan Source bidi overrides and Unicode tag smuggling | 2 | enforced-at-commit |
| [Test integrity](#test-integrity) | deleted tests, net assertion loss, `assert True`, new skips and `.only` | 2 | enforced-at-commit |
| **Also included** | | | |
| [Secrets & data leakage](#secrets--data-leakage) | credentials in a commit, session leaks in commit messages, uploads to unknown hosts | 3 | enforced-at-commit |
| [Destructive commands & hook bypass](#destructive-commands--hook-bypass) | `rm -rf /`, force push, hard reset, `DROP`, `--no-verify`, commits to `main`, `curl \| sh` | 5 | enforced-at-commit |
| [Agent self-protection & excessive agency](#agent-self-protection--excessive-agency) | an agent editing its own guardrails or CI, wildcard grants, unguarded sub-agents, unlisted MCP servers | 5 | enforced-at-commit |
| [Agent discipline & hygiene](#agent-discipline--hygiene) | oversized diffs, wasted tool calls, sloppy git habits | 8 | enforced-at-commit |
| [EU AI Act](#eu-ai-act) | Art. 5 prohibited practices, Annex III high-risk triage, Art. 50 transparency | 3 | advisory |

1,182 eval cases back these policies; 1,022 of them are replayed deterministically in CI
against a throwaway repo on every push. In the tables below, **Evals** is executed/total --
advisory cases report as *skipped*, never as *passing*, because there is nothing to replay.

---

## A normal day, by role

Your agent already asks before `rm -rf`. That was never the hard part. Built-in permission
prompts are generic, per-agent and per-laptop: they don't know your Java stack, your
accessibility baseline, your memory rules or your threat model. Chock makes your team's rules
part of the repo, the same for every agent and every developer.

| | Agent's built-in defaults | With Chock |
| :--- | :--- | :--- |
| **What it knows** | generic shell prompts: "allow this command?" | your stack -- 129 Java rules, agent code, accessibility, IAM, MCP, memory, supply chain |
| **Where it lives** | one person's settings, in one tool | plain files committed to the repo -- reviewed in PRs, travelling with every clone |
| **Which agents** | each agent, its own format and gaps | one policy compiled for Claude Code, Cursor, Copilot, Codex, Gemini CLI and the rest of the 15 adapters |
| **After the agent** | nothing at commit or in CI | gates run again as a git hook and a CI gate (`chock sync --ci`), catching what any agent or person missed |
| **When it says no** | a yes/no prompt the developer clicks through | a refusal that names the fix, so the agent can correct itself in the same turn |
| **Proof** | the vendor's word | 1,182 eval cases, 1,022 replayed in CI, and a coverage record for every policy × agent pair |

<details open>
<summary><strong>Java &amp; Kotlin developers</strong> -- Spring · Jakarta · Quarkus · Micronaut · Android</summary>

| | |
| :--- | :--- |
| **Agent writes** | a Spring repository method that puts `${id}` into a MyBatis query, or a controller that deserializes request bodies with Jackson default typing |
| **Chock** | refuses the write at the agent's own hook where the client has one, and again at commit; the refusal names the rule, its pack and the fix, so the agent can rewrite it with a bound parameter before you review it |
| **You get** | 129 rules in 16 packs, including 7 quality packs mirroring SpotBugs, Sonar, PMD and Checkstyle -- caught as the code is written, not in a scan a day later; only what the change adds is refused |
| **Policies** | `java-security` (enforced at commit) -- the team picks `allow` · `deny` · `ask` per pack once, in a guided page ("customize java security"), saved to `.chock/security.json` |

</details>

<details>
<summary><strong>Web &amp; UX designers</strong> -- ADA · Section 508 · WCAG</summary>

| | |
| :--- | :--- |
| **Agent writes** | a "cleanup" of a component that empties an `alt`, drops the `aria-label` on an icon button, hides a wrapper with `aria-hidden`, or deletes a flagged element instead of fixing it |
| **Chock** | refuses the change: restore the name, or say the element is decorative where a reviewer sees it. Adding a name is recorded and never questioned; rewording a label stays silent -- that is a copy decision |
| **You get** | accessibility work done for an ADA, Section 508 or WCAG audit can't quietly regress when an agent refactors the UI; markup whose name can't be decided stays silent instead of nagging. It guards the work -- it does not certify compliance |
| **Policies** | `no-a11y-regression` (enforced at commit, and when the agent writes the file) -- guards `alt`, `aria-label`, `<label>`, `lang`, `aria-hidden`, `role="presentation"` |

</details>

<details>
<summary><strong>Everyone using agent memory</strong> -- <code>MEMORY.md</code> · <code>CLAUDE.local.md</code> · the agent's own stores</summary>

| | |
| :--- | :--- |
| **Agent writes** | a pasted diff, a code block over 20 lines, the same line twice -- or an API key -- into memory that every future session will read |
| **Chock** | refuses those memory writes at commit and at agent tool-use, including Claude Code's and Copilot's memory stores outside the repo, with no waiver. `memory-discipline` steers what to keep: decisions and facts that can't be re-derived, atomic, de-duplicated, verified before reuse |
| **You get** | memory that stays small, true and secret-free from session to session. `memory-discipline` maps to MITRE ATLAS AML.T0080 (memory poisoning); OWASP ASI06 has the advisory `owasp-asi06-memory-context-poisoning` policy and the opt-in `prompt-memory` pack of `agentic-code-security`. `guard-memory-writes` keeps the memory files themselves clean but declares no OWASP mapping |
| **Policies** | `guard-memory-writes` (enforced at commit) · `memory-discipline` (advisory) |

</details>

<details>
<summary><strong>AppSec &amp; OWASP owners</strong> -- OWASP Top 10 for Agentic Applications</summary>

| | |
| :--- | :--- |
| **Today** | your checklist lives in a wiki; whether each agent, on each laptop, followed it is anyone's guess |
| **Chock** | each of ASI01–ASI10 has a policy in the repo. 7 of the 10 also have a slice enforced at commit (ASI01–ASI05, ASI07, ASI09), ASI10 has an in-agent slice, and ASI06 and ASI08 are advisory only; beyond those slices the rule text steers the agent -- least agency, validated tool parameters, sandboxed execution, the raw action shown at approval |
| **You get** | the part of your review checklist a diff can show, run on every commit -- plus 29 rules for teams building agents on LangChain, LangGraph, CrewAI, AutoGen, mem0, the OpenAI Agents SDK, the Claude Agent SDK or MCP. The 10/10 coverage claim is re-derived on every build |
| **Policies** | `owasp-asi01` … `owasp-asi10` (advisory, with enforced slices) · `agentic-code-security` (enforced at commit) |

</details>

<details>
<summary><strong>Threat modeling</strong> -- MITRE ATLAS, from technique ID to the control that answers it</summary>

11 ATLAS techniques are mapped in the policy manifests. Every mapping is recorded as
`coverage: partial` -- the slice a diff or a tool call can show.

| ATLAS | Technique, as the manifest scopes it | Answered by |
| :--- | :--- | :--- |
| `AML.T0051` | LLM prompt injection | `block-invisible-unicode` (commit) · `injection-defense`, `owasp-asi01-agent-goal-hijack` (advisory) |
| `AML.T0080` | agent context and memory poisoning | `memory-discipline`, `owasp-asi06-memory-context-poisoning` (advisory) |
| `AML.T0081` | modify agent configuration | `protect-agent-config` (in-agent) |
| `AML.T0083` | credentials from agent configuration | `protect-agent-config` (in-agent) · `block-wildcard-agent-permissions` (commit) |
| `AML.T0010` | supply chain compromise | `verify-mcp-allowlist`, `verify-dependency-exists` (commit) · `owasp-asi04-agentic-supply-chain` (advisory) |
| `AML.T0109` | rug pull through a re-tagged or floating version | `pin-github-actions`, `block-unpinned-agent-components` (commit) · `owasp-asi04-agentic-supply-chain` (advisory) |
| `AML.T0110` | poisoned tool or MCP server acquisition | `block-unpinned-agent-components` (commit) · `owasp-asi04-agentic-supply-chain` (advisory) |
| `AML.T0055` | unsecured credentials | `scan-secrets` (commit) |
| `AML.T0025` | exfiltration | `block-unapproved-egress` (in-agent) |
| `AML.T0050` | command and scripting interpreter | `block-unsafe-code-execution` (commit) |
| `AML.T0101` | data destruction via agent tools | `block-destructive-commands` (commit) · `rtk-dangerous-actions-blocker` (in-agent) |

New entries are scored weekly, by a person, in
[chock-threat-intel](https://github.com/open-coder-ai/chock-threat-intel): enforced, advisory,
or `policy wanted`.

</details>

<details>
<summary><strong>Platform &amp; security governance</strong> -- policy as code, reviewed in PRs</summary>

| | |
| :--- | :--- |
| **Today** | every team, agent and laptop configured differently; no record of which control ran where -- and an agent can edit its own settings |
| **Chock** | one policy compiles to git hooks, a CI gate (`chock sync --ci`) and native agent hooks. Installs are hash-pinned in `chock.lock`, and `--verify-sha` refuses a pack that does not hash to the value you name. Agents are refused when they edit their own guardrails or CI workflows |
| **You get** | a coverage record per policy × agent (`coverage.json`, `none` where no surface can carry it), policies reviewed like code, deterministic enforcement with no LLM calls and no network access -- plus advisory EU AI Act policies |
| **Policies** | `protect-agent-config`, `protect-ci-workflows` (in-agent) · `protect-commit-privacy` (enforced at commit) |

</details>

### Guardrails that teach

Every refusal names the safe alternative, so the agent can rewrite in the same turn -- fewer
review round-trips, not more friction. Quoted from the policies' own block messages:

> **`block-unsafe-code-execution`** -- "Dynamic execution primitive detected. Replace it with a
> parameterized API (subprocess argument vector, safe_load, a real parser), …"

> **`block-unpinned-agent-components`** -- "Unpinned agent component detected. Pin the version
> (name@1.2.3, image:tag) so what runs tomorrow is what was reviewed today, …"

> **`block-wildcard-iam`** -- "Broad privilege grant detected. Scope Action and Resource to
> what the task needs, …"

---

## Security coverage by area

Tiers: `enforced-at-commit` -- the command exits non-zero, the commit does not happen ·
`in-agent` -- best-effort: the tool call is refused before it runs, if the pre-tool hook
runs (it fails open if the hook crashes) · `advisory` -- text an agent reads and may or may
not follow. Most `enforced-at-commit` gates also check the agent's own writes -- before a
write lands, where the client has a pre-tool hook (best-effort), and again at the end of
its turn -- so a refusal usually arrives while the agent is still working. The commit is
where the refusal is guaranteed; the tier names that point, not the first one.

### Secure code: Java / Kotlin

<details open>
<summary><code>java-security</code> -- 129 rules in 16 packs, each citing its CWE</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`java-security`](docs/java-security/) | injection (SQL, command, code, SpEL, LDAP, XPath, template), XXE, SSRF, unsafe deserialization, path traversal and zip slip, weak crypto and trust-all TLS, disabled Spring Security, exposed actuator and secrets, known-exploited dependency versions, exported Android components | 107/115 | enforced-at-commit |

Judged as the agent writes and again at commit. Only what the change adds is refused: a
finding on lines the change leaves alone never blocks it. The correct sibling of each rule --
`#{}` and bind parameters, `th:text`, `parseClaimsJws`, AES-GCM -- stays silent.

| Pack | Rules | Covers |
| :--- | ---: | :--- |
| `java` | 18 | the JDK: command, code, reflection, LDAP and XPath injection, XML parsers (XXE), outbound URLs (SSRF), archives (zip slip), file paths, Java and polymorphic deserialization, unverified JWT |
| `crypto` | 10 | weak ciphers, digests and signatures, insecure random, fixed seeds and IVs, trust-all trust managers and hostname verifiers, hard-coded credentials |
| `spring` | 17 | CSRF disabled, catch-all `permitAll`, weak password encoders, SpEL injection, open redirect, actuator exposure, secrets in `application.properties`/`.yml` |
| `jakarta` | 8 | Servlet, JAX-RS, JSF, `web.xml`; Struts; Quarkus, Micronaut, Helidon, Vert.x, Dropwizard |
| `persistence` | 5 | SQL/JPQL/HQL built by concatenation, MyBatis `${}`, NoSQL injection, unsafe JDBC URLs, destructive DDL |
| `templates` | 5 | unescaped output and run-time templates in Thymeleaf, JSP, JSF, FreeMarker, Velocity, Pebble, Mustache, Handlebars |
| `logging` | 4 | Log4j lookups, secrets written to logs, stack traces sent to the caller |
| `build` | 4 | plain-HTTP Maven/Gradle repositories, missing checksums, Log4Shell- and Spring4Shell-class versions |
| `android` | 8 | WebView JS bridges, ignored TLS errors, world-readable files, `debuggable`/`allowBackup`, exported components |
| `bugs` · `concurrency` · `resources` · `exceptions` · `performance` · `style` · `testing` | 50 | quality packs mirroring SpotBugs, Sonar, PMD and Checkstyle |

Every rule and pack is `allow`, `deny` or `ask` in `.chock/security.json`; absent means
`deny`. `ask` prompts a person at the terminal and refuses when there is nobody to ask. Say
"customize java security" to your agent to open the guided page, or write the file yourself:

```json
{
  "version": 2,
  "packs": {
    "android": { "verdict": "allow" },
    "style": { "verdict": "allow" },
    "persistence": { "rules": { "persistence-destructive-ddl": "ask" } }
  }
}
```

A line is waived only by a human reviewer, with `// chock: allow <rule-id>`; in the agent, a
waiver counts once a human has committed it.

</details>

### Secure code: agent code & cloud privilege

<details>
<summary><code>agentic-code-security</code> -- 29 rules in 10 packs for agent frameworks, plus 2 narrow gates</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`agentic-code-security`](docs/agentic-code-security/) | model-written code run on the host, unpinned MCP servers and models, shell-reaching tools, approvals switched off, whole-environment and credential-store leaks, TLS verification off, unbounded loops, SQL and `eval` built from strings, stripped provenance markers | 136/141 | enforced-at-commit |
| [`block-unsafe-code-execution`](docs/block-unsafe-code-execution/) | bare `eval`/`exec`, `shell=True`, `os.system`, `pickle`/`marshal` loads, `yaml.load` without `SafeLoader`, `execSync`, `new Function` | 13/13 | enforced-at-commit |
| [`block-wildcard-iam`](docs/block-wildcard-iam/) | `"Action": "*"` / `"Resource": "*"`, `AdministratorAccess`, GCP `roles/owner` and `roles/editor`, Terraform wildcard lists | 12/12 | enforced-at-commit |

`agentic-code-security` reads Python and TypeScript using **AutoGen, CrewAI, LangChain,
LangGraph, mem0, the OpenAI Agents SDK and the Claude Agent SDK**, MCP servers and clients
(`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`,
`.codex/config.toml`, `.gemini/settings.json`) and agent `docker-compose` files. Each
refusal names the rule, its CWE and its OWASP ASI entry.

| Pack | ASI | Example refusal |
| :--- | :--- | :--- |
| `exec` | ASI05 | AutoGen `use_docker: False`, CrewAI `code_execution_mode="unsafe"`, LangChain `allow_dangerous_code=True` |
| `supply` | ASI04 | unpinned MCP launch commands, `uvx` git installs without a commit, plain-HTTP MCP, `trust_remote_code` |
| `tools` | ASI02 | a tool parameter reaching a shell, shell-tool instantiation |
| `approval` | ASI02, ASI09 | hosted MCP approval set to never, Claude Agent SDK permission bypass, auto-approved write tools |
| `identity` | ASI03 | the whole host environment or a credential store handed to the agent |
| `comms` | ASI07 | TLS verification switched off |
| `bounds` | ASI08 | unbounded turns, very high recursion or iteration limits |
| `prompt-memory` | ASI01, ASI06 | untrusted input in a system message, unscoped mem0 memory |
| `code` | -- | dynamic `eval`/`exec`, SQL built from strings |
| `provenance` | EU AI Act Art. 50 | a provenance marker the file carried at HEAD, removed |

Verdicts are `allow` or `deny` per pack or rule in `.chock/agentic-security.json`; `bounds`,
`prompt-memory` and one `supply` rule start as `allow`. The full rule catalogue is in
[`agentic-security/agentic-code-security/references/rule-catalogue.md`](agentic-security/agentic-code-security/references/rule-catalogue.md).

</details>

### Supply chain

<details>
<summary>3 policies -- dependency allowlist, SHA-pinned Actions, @latest</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`verify-dependency-exists`](docs/verify-dependency-exists/) | a new dependency in `requirements.txt`, `pyproject.toml`, `package.json` or `go.mod` absent from your allowlist (opt-in) | 9/9 | enforced-at-commit |
| [`pin-github-actions`](docs/pin-github-actions/) | any `owner/repo@ref` in `.github/workflows` or `.github/actions` that is not a full commit SHA -- GitHub's own `actions/*` included | 17/17 | enforced-at-commit |
| [`block-unpinned-agent-components`](docs/block-unpinned-agent-components/) | `npx`/`uvx`/`bunx` launches at `@latest`, `"@latest"` in agent config, `:latest` images | 12/12 | enforced-at-commit |

</details>

### OWASP Top 10 for Agentic Applications

<details>
<summary>10/10 risks have a policy -- 7 with a slice enforced at commit, 1 in-agent, 2 advisory only</summary>

These govern the agentic system you are *building*; the areas above govern the agent doing
the building. Each `owasp-asi*` policy is advisory: whether a tool grant is "least agency" is
a judgement about your architecture, not a pattern a gate can match. Where a risk has a
slice a diff can literally show, a narrow gate enforces that slice.

**10/10 risks have a policy · 7 have a slice enforced at commit · 1 more has an in-agent slice · 2 are advisory only · 0 are fully covered.** Every mapping is `partial` and comes from the policy manifests' `compliance.owasp_asi` block, not from this page.

| Risk | Policy (advisory) | Slice enforced at commit | Slice in-agent (best-effort) | Also steers |
| :--- | :--- | :--- | :--- | :--- |
| ASI01 Agent goal hijack | [`owasp-asi01-agent-goal-hijack`](docs/owasp-asi01-agent-goal-hijack/) | [`block-invisible-unicode`](docs/block-invisible-unicode/) | -- | [`injection-defense`](docs/injection-defense/) |
| ASI02 Tool misuse | [`owasp-asi02-tool-misuse`](docs/owasp-asi02-tool-misuse/) | [`agentic-code-security`](docs/agentic-code-security/) (`tools`, `approval`), [`block-destructive-commands`](docs/block-destructive-commands/) | [`block-curl-pipe-sh`](docs/block-curl-pipe-sh/), [`block-unapproved-egress`](docs/block-unapproved-egress/), [`protect-ci-workflows`](docs/protect-ci-workflows/), [`rtk-dangerous-actions-blocker`](docs/rtk-dangerous-actions-blocker/) | -- |
| ASI03 Identity & privilege abuse | [`owasp-asi03-identity-privilege-abuse`](docs/owasp-asi03-identity-privilege-abuse/) | [`agentic-code-security`](docs/agentic-code-security/) (`identity`), [**`block-wildcard-iam`**](docs/block-wildcard-iam/), [`block-wildcard-agent-permissions`](docs/block-wildcard-agent-permissions/) | [`protect-agent-config`](docs/protect-agent-config/) | -- |
| ASI04 Agentic supply chain | [`owasp-asi04-agentic-supply-chain`](docs/owasp-asi04-agentic-supply-chain/) | [`agentic-code-security`](docs/agentic-code-security/) (`supply`), [**`block-unpinned-agent-components`**](docs/block-unpinned-agent-components/), [`pin-github-actions`](docs/pin-github-actions/), [`verify-dependency-exists`](docs/verify-dependency-exists/), [`verify-mcp-allowlist`](docs/verify-mcp-allowlist/) | -- | -- |
| ASI05 Unexpected code execution | [`owasp-asi05-unexpected-code-execution`](docs/owasp-asi05-unexpected-code-execution/) | [`agentic-code-security`](docs/agentic-code-security/) (`exec`), [**`block-unsafe-code-execution`**](docs/block-unsafe-code-execution/) | -- | [`code-safety`](docs/code-safety/) |
| ASI06 Memory & context poisoning | [`owasp-asi06-memory-context-poisoning`](docs/owasp-asi06-memory-context-poisoning/) | -- | -- | `agentic-code-security` `prompt-memory` pack (off by default; switch on in `.chock/agentic-security.json`) |
| ASI07 Insecure inter-agent communication | [`owasp-asi07-insecure-inter-agent-communication`](docs/owasp-asi07-insecure-inter-agent-communication/) | [`agentic-code-security`](docs/agentic-code-security/) (`comms`) | -- | -- |
| ASI08 Cascading failures | [`owasp-asi08-cascading-failures`](docs/owasp-asi08-cascading-failures/) | -- | -- | `agentic-code-security` `bounds` pack (off by default; switch on in `.chock/agentic-security.json`) |
| ASI09 Human-agent trust exploitation | [`owasp-asi09-human-agent-trust`](docs/owasp-asi09-human-agent-trust/) | [`agentic-code-security`](docs/agentic-code-security/) (`approval`) | -- | -- |
| ASI10 Rogue agents | [`owasp-asi10-rogue-agents`](docs/owasp-asi10-rogue-agents/) | -- | [`block-unguarded-agent-spawn`](docs/block-unguarded-agent-spawn/) | -- |

The bold gates are the narrow siblings named for exactly what they block, so the advisory
policy never claims an enforcement it does not have:

| Gate | Blocks | Evals | Slice of |
| :--- | :--- | ---: | :--- |
| [`block-unsafe-code-execution`](docs/block-unsafe-code-execution/) | bare `eval`/`exec`, `shell=True`, unsafe deserialization | 13/13 | ASI05 |
| [`block-wildcard-iam`](docs/block-wildcard-iam/) | `"Action": "*"`, `AdministratorAccess`, `roles/owner` | 12/12 | ASI03 |
| [`block-unpinned-agent-components`](docs/block-unpinned-agent-components/) | `npx -y server@latest`, `:latest` images | 12/12 | ASI04 |

The pattern is the same one `base/` uses: `code-safety` advises broadly while
`scan-secrets` blocks narrowly. The gate is not the rule promoted -- it is the greppable
fraction, enforced honestly, with the judgement half still labelled advisory. The 10/10
claim is re-derived on every build (CI fails if the staged adopter reports an uncovered
control); what `partial` versus `full` means is in [docs/coverage.md](docs/coverage.md).

</details>

### Accessibility (ADA / Section 508 / WCAG)

<details>
<summary><code>no-a11y-regression</code> -- accessibility work, once done, cannot silently regress</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`no-a11y-regression`](docs/no-a11y-regression/) | a change that retracts an accessible name an element already had: `alt` emptied, `aria-label` removed, `aria-hidden` or `role="presentation"` added, a `<label>` or `lang` removed, a flagged element deleted instead of fixed | 7/20 | enforced-at-commit |

Teams remediating for ADA, Section 508 or WCAG usually track violations -- and neither a
description replaced by `alt=""` nor a flagged element deleted outright produces a violation,
so both pass every violation report. This gate compares against the previous revision
instead, at commit and again when the agent writes the file. Adding a name is recorded and
never questioned; a reworded label is a copy decision and stays silent. It keeps compliance
work from regressing; it does not certify compliance.

</details>

### Memory guardrails

<details>
<summary>2 policies -- what an agent may write into the memory every later session reads</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`guard-memory-writes`](docs/guard-memory-writes/) | memory files that paste git history, hold long code blocks, repeat lines or store a secret -- and, at tool use, the agent's own stores outside the repo | 24/25 | enforced-at-commit |
| [`memory-discipline`](docs/memory-discipline/) | nothing mechanically: persist decisions, never file contents or git history | 0/3 | advisory |

`memory-discipline` maps to MITRE ATLAS AML.T0080. OWASP ASI06 (memory and context poisoning)
is covered by the advisory [`owasp-asi06-memory-context-poisoning`](docs/owasp-asi06-memory-context-poisoning/)
policy and the opt-in `prompt-memory` pack of `agentic-code-security`; no gate enforces it.

</details>

### Prompt injection

<details>
<summary>2 policies -- bidi and tag Unicode, instructions in content</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`block-invisible-unicode`](docs/block-invisible-unicode/) | bidi override, embedding and isolate controls (Trojan Source, CVE-2021-42574) and Unicode tag characters -- instructions hidden from reviewers but legible to agents. Other invisible characters (zero-width space, U+FEFF, U+2060, variation selectors) are not matched | 14/14 | enforced-at-commit |
| [`injection-defense`](docs/injection-defense/) | nothing mechanically: instructs the agent to treat instructions inside content as data and to confirm egress | 0/4 | advisory |

</details>

### Test integrity

<details>
<summary>2 policies -- an agent must not turn CI green by weakening the tests</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`protect-test-integrity`](docs/protect-test-integrity/) | a deleted test file, a net loss of assertions, a vacuous `assert True`/`expect(true)` -- Python, JS/TS, Go, Java | 17/19 | enforced-at-commit |
| [`block-test-skips`](docs/block-test-skips/) | new `@pytest.mark.skip`, `it.skip`, `.only`, `@Disabled`, `t.Skip` in test files | 25/26 | enforced-at-commit |

</details>

**Also included -- the shell, git and agent-config guards.** Agents ship their own
prompts for these; Chock adds a policy committed to the repo, the same for every agent.

### Secrets & data leakage

<details>
<summary>3 policies -- credentials, commit narration, egress</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`scan-secrets`](docs/scan-secrets/) | credentials, keys and tokens in staged changes, and whole secret files by path: `.env*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` | 32/32 | enforced-at-commit |
| [`protect-commit-privacy`](docs/protect-commit-privacy/) | commit messages and PR bodies that narrate the agent's conversation or leak a session link | 35/35 | enforced-at-commit |
| [`block-unapproved-egress`](docs/block-unapproved-egress/) | `curl -d`/`-F`/`-X POST`, `wget --post-file`, `Invoke-WebRequest -Method POST` to a host off the allowlist; fetches pass | 49/49 | in-agent |

</details>

### Destructive commands & hook bypass

<details>
<summary>5 policies -- rm -rf, force push, --no-verify, main, curl | sh</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`block-destructive-commands`](docs/block-destructive-commands/) | `rm -rf /`, force push, hard reset, `terraform destroy`, `dropdb`, `helm uninstall`, `kubectl delete`, `aws s3 rm --recursive`, `gcloud … delete` | 80/80 | enforced-at-commit |
| [`rtk-dangerous-actions-blocker`](docs/rtk-dangerous-actions-blocker/) | `rm -rf /`, force push, credential-file reads, `DROP`/`TRUNCATE`; **asks** before `git reset --hard`, `git clean -f` | 92/92 | in-agent |
| [`block-no-verify`](docs/block-no-verify/) | `--no-verify`, and an agent setting the overrides meant for a person | 74/74 | in-agent |
| [`protect-main-branch`](docs/protect-main-branch/) | commits and pushes straight to `main`/`master` | 4/4 | enforced-at-commit |
| [`block-curl-pipe-sh`](docs/block-curl-pipe-sh/) | a download piped into an interpreter -- `curl … \| sh`, `bash -c "$(curl …)"`, `iwr … \| iex` | 34/34 | in-agent |

</details>

### Agent self-protection & excessive agency

<details>
<summary>5 policies -- an agent must not widen or disarm its own guardrails</summary>

| Policy | Refuses | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`protect-agent-config`](docs/protect-agent-config/) | shell edits to the agent's own instruction, permission and enforcement files, guard sources included | 79/79 | in-agent |
| [`protect-ci-workflows`](docs/protect-ci-workflows/) | shell writes to `.github/workflows/`, `.github/actions/`, `.github/dependabot.yml` | 36/36 | in-agent |
| [`block-wildcard-agent-permissions`](docs/block-wildcard-agent-permissions/) | committed everything-grants: bare-wildcard shell grants, allow-everything tool lists | 17/17 | enforced-at-commit |
| [`block-unguarded-agent-spawn`](docs/block-unguarded-agent-spawn/) | `claude --dangerously-skip-permissions`, `codex --yolo`, `gemini --yolo` (OWASP ASI10) | 25/25 | in-agent |
| [`verify-mcp-allowlist`](docs/verify-mcp-allowlist/) | an MCP server in `.mcp.json` that is not on the allowlist, or an allowed name pointed at a different source | 65/65 | enforced-at-commit |

</details>

### Agent discipline & hygiene

<details>
<summary>8 policies -- diff size, tool-call waste, and the habits a reviewer would otherwise repeat</summary>

| Policy | Does | Evals | Tier |
| :--- | :--- | ---: | :--- |
| [`limit-diff-size`](docs/limit-diff-size/) | **asks** (exit 3) before a commit over 500 changed lines; a person answers, an agent's commit cannot | 3/11 | enforced-at-commit |
| [`firecrawl-fallback-only`](docs/firecrawl-fallback-only/) | warns (never blocks) on a Firecrawl call before a native fetch has failed | 0/8 | in-agent |
| [`token-efficiency`](docs/token-efficiency/) | warns (never blocks) on a third read of an unchanged file, a fourth retry of a failing command | 0/7 | in-agent |
| [`agent-discipline`](docs/agent-discipline/) | read before edit, verify before done, never fix a test by deleting an assertion | 0/3 | advisory |
| [`code-safety`](docs/code-safety/) | avoid `eval`/`exec` and unsanitized SQL; points at `scan-secrets` and `verify-dependency-exists` | 0/4 | advisory |
| [`git-safety`](docs/git-safety/) | feature branches, atomic commits; points at the destructive-command and hook gates | 0/4 | advisory |
| [`context-hygiene`](docs/context-hygiene/) | replace resolved content with path references, prune stale context | 0/3 | advisory |
| [`chock-mise`](docs/chock-mise/) | toolchain conventions for mise-managed repos | 0/7 | advisory |

</details>

### EU AI Act

<details>
<summary>3 compliance policies -- jurisdiction-specific, in <code>compliance/</code></summary>

Everything above applies to any repo; these only earn their place if the regulation reaches
you.

| Policy | Covers | Evals | In force |
| :--- | :--- | ---: | :--- |
| [`eu-ai-act-prohibited-practices`](docs/eu-ai-act-prohibited-practices/) | Art. 5 -- social scoring, face scraping, workplace emotion inference, NCII/CSAM | 0/6 | now |
| [`eu-ai-act-high-risk-triage`](docs/eu-ai-act-high-risk-triage/) | Annex III domains, Articles 9–15; warns (never blocks) on added code that scores, ranks or screens people | 4/11 | 2027-12-02 |
| [`eu-ai-act-transparency`](docs/eu-ai-act-transparency/) | Art. 50 -- AI disclosure, machine-readable marking of synthetic output, deepfake labelling | 0/6 | now |

Advisory, like everything else with no mechanism. Regulatory scoping is judgement, and a
keyword gate here would block on `emotion_recognition` in a comment.

</details>

### Threat intelligence

[chock-threat-intel](https://github.com/open-coder-ai/chock-threat-intel) publishes a weekly,
human-reviewed digest mapping MITRE ATLAS and OWASP entries to a catalog answer -- enforced,
advisory, or `policy wanted`. A `policy wanted` row is the best place to start contributing.

---

## The tiers: guardrails, not guarantees

The difference between advice and a control has to be visible, because the failure mode of
governance tooling is that everyone believes it is doing more than it is. So every policy is
labelled with what it actually reaches -- stated up front, because 20 of the 48 are
advisory, and that is the number most catalogs would round up:

| | What it means | How many |
| :--- | :--- | ---: |
| `enforced-at-commit` | the command exits non-zero, the commit does not happen | 19 |
| `in-agent` | the tool call is refused before it runs, if the hook itself runs | 9 |
| `advisory` | text an agent reads and may or may not follow | 20 |

The framework's top tier, `enforced` -- refused in the agent with no way for the agent to
route around it -- is reached by no agent today, and nothing here claims it.

<img alt="48 policies: 19 enforced-at-commit, 9 in-agent, 20 advisory" src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/coverage-matrix.svg">

The same distribution, in the shared open-coder-ai figure language and readable in either
theme:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/figures/enforcement-dark.svg">
  <img alt="Of 48 chock-catalog policies, 19 are enforced at commit and 9 more are enforced in-agent, for 28 enforced overall -- 20 are advisory only, read by the agent but backed by no mechanism." src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/figures/enforcement-light.svg" width="760">
</picture>

<details>
<summary>All 28 enforced policies, by tier</summary>

**Enforced at commit** — declarative gates and commit-time scripts, verified by replaying
their own gate against a throwaway repo on every push.

| Policy | Blocks | Evals |
| :--- | :--- | ---: |
| [`protect-main-branch`](docs/protect-main-branch/) | commits and pushes to `main`/`master` | 4/4 |
| [`scan-secrets`](docs/scan-secrets/) | credentials in staged changes | 32/32 |
| [`verify-dependency-exists`](docs/verify-dependency-exists/) | packages absent from your allowlist | 9/9 |
| [`block-invisible-unicode`](docs/block-invisible-unicode/) | bidi-override and tag-block Unicode in staged changes -- Trojan Source and instructions hidden from reviewers but legible to agents | 14/14 |
| [`block-wildcard-agent-permissions`](docs/block-wildcard-agent-permissions/) | committed everything-grants -- bare-wildcard shell grants and allow-everything tool lists -- that hand an agent unlimited tool authority | 17/17 |
| [`pin-github-actions`](docs/pin-github-actions/) | any `owner/repo@ref` in `.github/workflows` or `.github/actions` pinned to a movable tag or branch instead of a full commit SHA -- GitHub's own `actions/*` included -- so a re-tagged or compromised release can't change what CI runs; SHA pins and local actions pass | 17/17 |
| [`block-wildcard-iam`](docs/block-wildcard-iam/) | wildcard Action or Resource in an IAM policy document, `AdministratorAccess` attachment, GCP `roles/owner` or `roles/editor`, and Terraform wildcard action or resource lists -- the mechanizable slice of ASI03 | 12/12 |
| [`block-unpinned-agent-components`](docs/block-unpinned-agent-components/) | agent components pulled at an unpinned version -- `npx`/`uvx`/`bunx` launches at `@latest` (the standard MCP server idiom), quoted `"@latest"` in agent config, and `:latest` image tags -- the mechanizable slice of ASI04 | 12/12 |
| [`block-unsafe-code-execution`](docs/block-unsafe-code-execution/) | bare `eval`/`exec`, shell-mode subprocess calls, `os.system`, `pickle`/`marshal` loads, `yaml.load` without `SafeLoader`, `execSync` and `new Function` -- a best-effort line scan over the mechanizable slice of ASI05 | 13/13 |
| [`no-a11y-regression`](docs/no-a11y-regression/) | a change that destroys an accessibility assertion the previous revision carried -- a description replaced by `alt=""`, or a flagged element deleted rather than fixed; neither produces a violation, so both pass every violation report; judged at commit and again when the agent writes the file and at turn end | 7/20 |
| [`java-security`](docs/java-security/) | 129 rules in 16 packs, each citing its CWE and evidence, as they are written and at the commit -- core Java, crypto and TLS, Spring, Jakarta EE and other frameworks, persistence, templates, logging, Maven and Gradle builds, Android, and 7 quality packs mirroring SpotBugs, Sonar, PMD and Checkstyle -- each pack or rule `allow\|deny\|ask` in `.chock/security.json` | 107/115 |
| [`protect-test-integrity`](docs/protect-test-integrity/) | Blocks a deleted test file, a net loss of assertions across the change, and an added vacuous assertion (`assert True`, `expect(true)`) in Python, JS/TS, Go and Java test layouts -- commit only, waiver `chock: allow test-integrity` | 17/19 |
| [`block-test-skips`](docs/block-test-skips/) | Blocks newly added test skips and focus markers (`@pytest.mark.skip`, `it.skip`, `.only`, `@Disabled`, `t.Skip`) in test files, at commit and at agent tool-use -- judged against HEAD, waiver `chock: allow test-skip` at commit only | 25/26 |
| [`limit-diff-size`](docs/limit-diff-size/) | **Asks** (exit 3) before a commit whose staged added plus removed lines exceed 500 (`CHOCK_DIFF_LIMIT`), not counting lockfiles, vendored or generated paths and binaries -- a person answers with `CHOCK_ALLOW=limit-diff-size` (or `CHOCK_ALLOW_LARGE_DIFF=1`); an agent's commit cannot | 3/11 |
| [`guard-memory-writes`](docs/guard-memory-writes/) | Refuses memory files (`MEMORY.md`, `CLAUDE.local.md`, `.claude/memory/`) that paste git history, hold a code block over 20 lines, repeat a line or store a secret -- at commit and at agent tool-use, no waiver | 24/25 |
| [`agentic-code-security`](docs/agentic-code-security/) | 29 rules in 10 packs for agent code and agent config -- AutoGen, CrewAI, LangChain, LangGraph, mem0, the OpenAI Agents and Claude Agent SDKs, MCP servers and clients -- each pack or rule `allow\|deny` in `.chock/agentic-security.json` | 136/141 |
| [`block-destructive-commands`](docs/block-destructive-commands/) | `rm -rf /`, force push, hard reset, `terraform destroy`, `dropdb`, `helm uninstall`, `docker volume rm`, `aws s3 rm --recursive`, `gcloud … delete` | 80/80 |
| [`verify-mcp-allowlist`](docs/verify-mcp-allowlist/) | a shell write to `.mcp.json` adding an MCP server not on the allowlist, or changing an allowed server's command/args/url to point elsewhere (including one renamed to an allowed name) — the allowlist ships inside the guard script itself, protected the same way as any other policy's guard source; a matching entry passes without a human approval each time | 65/65 |
| [`protect-commit-privacy`](docs/protect-commit-privacy/) | commit messages and `gh pr create`/`edit` bodies that narrate the development conversation (or leak a session link) instead of describing the change — a leak class that only exists once an agent authors the commit | 35/35 |

**Enforced before the tool runs** — guard scripts consulted before the agent executes a
command. `chock sync` wires these natively on the 11 agents with an in-agent surface,
Claude Code, Cursor, Codex, Copilot CLI and VS Code among them; Codex additionally requires a
per-hook trust review before its hooks run.

| Policy | Refuses | Evals |
| :--- | :--- | ---: |
| [`block-no-verify`](docs/block-no-verify/) | `--no-verify`, which bypasses every gate above, and an agent setting or clearing the overrides meant for a person (`CHOCK_ALLOW`, `CHOCK_AGENT_COMMIT`, `CLAUDECODE`, `AI_AGENT`) in its own command | 74/74 |
| [`protect-agent-config`](docs/protect-agent-config/) | shell edits to the agent's own instruction, permission and enforcement files (now including the policy guard sources themselves) -- self-modification refused up front | 79/79 |
| [`block-curl-pipe-sh`](docs/block-curl-pipe-sh/) | piping a network download into a shell or script interpreter — `curl … \| sh`, `wget … \| bash`, `curl … \| python`, `bash -c "$(curl …)"`, `iwr … \| iex` — while download-to-file and pipes into non-interpreter tools stay allowed | 34/34 |
| [`protect-ci-workflows`](docs/protect-ci-workflows/) | shell writes to the CI/CD config that gates a change — `.github/workflows/`, `.github/actions/`, `.github/dependabot.yml` — so an agent can't delete or loosen the checks reviewing its own work; reads and `chock sync` pass | 36/36 |
| [`block-unapproved-egress`](docs/block-unapproved-egress/) | a network client that uploads data — `curl -d`/`-F`/`--upload-file`, `-X POST`, `wget --post-file`, `Invoke-WebRequest -Method POST` — to a host outside the egress allowlist; fetch-only traffic and `pip install` pass. A tool-time floor, not a network sandbox | 49/49 |
| [`rtk-dangerous-actions-blocker`](docs/rtk-dangerous-actions-blocker/) | **carved out for [rtk-ai/rtk#1007](https://github.com/rtk-ai/rtk/issues/1007)**: rtk's own decision table — refuses `rm -rf /`, force push, credential-file reads (`.env`, `*.pem`, `~/.ssh`), `DROP`/`TRUNCATE` through psql and mysql; **asks** (exit 3) before `rm -rf` on an unlisted relative path, `git reset --hard`, `git clean -f`, `docker system prune`; skips file checks inside `docker exec`, and reads through rtk's own `rtk` prefix. The worked example of carving a policy out for one agent | 92/92 |
| [`block-unguarded-agent-spawn`](docs/block-unguarded-agent-spawn/) | Refuses launching a coding agent with its approvals or sandbox off (`claude --dangerously-skip-permissions`, `codex --yolo`, `gemini --yolo`); OWASP ASI10. | 25/25 |
| [`firecrawl-fallback-only`](docs/firecrawl-fallback-only/) | warns (never blocks) on a Firecrawl call when no WebFetch, WebSearch or `curl`/`wget` has failed earlier in the session, read from chock's session log | 0/8 |
| [`token-efficiency`](docs/token-efficiency/) | warns (never blocks) on the third `Read` of an unchanged file and on a fourth attempt at a command that failed three times | 0/7 |

</details>

<details>
<summary>All 20 advisory policies</summary>

**Advisory** — rule text compiled into agent context. No mechanism, no executed evals.

- base: [`agent-discipline`](docs/agent-discipline/) · [`code-safety`](docs/code-safety/) ·
  [`context-hygiene`](docs/context-hygiene/) · [`chock-mise`](docs/chock-mise/) ·
  [`git-safety`](docs/git-safety/) · [`injection-defense`](docs/injection-defense/) ·
  [`memory-discipline`](docs/memory-discipline/)
- compliance: [`eu-ai-act-transparency`](docs/eu-ai-act-transparency/) ·
  [`eu-ai-act-prohibited-practices`](docs/eu-ai-act-prohibited-practices/) ·
  [`eu-ai-act-high-risk-triage`](docs/eu-ai-act-high-risk-triage/)
- agentic-security: `owasp-asi01` … `owasp-asi10`, listed under
  [OWASP Top 10 for Agentic Applications](#owasp-top-10-for-agentic-applications)

</details>

Every policy has [its own page](docs/) — what it solves, how it works, which primitive it
becomes, and what is safe to change.

---

## It actually blocks the commit

<img src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/demo.gif" width="760" alt="Terminal session: chock add scan-secrets and protect-main-branch are installed, a commit containing an AWS key is blocked, the same commit passes once the key is read from the environment instead, and a commit straight to main is blocked next.">

This is the session that recording shows — real output from a real repository, not written
to look like it was. The full seven-step transcript, including the passing commit once the
key is removed, is in [docs/demo-session.md](docs/demo-session.md); here is the shape of it.

Onboard a repo and adopt scan-secrets and protect-main-branch, on a feature branch:

```console
$ chock init .
Initialized Chock in …
Policies: none. This repo enforces nothing yet.

$ chock add scan-secrets
Added scan-secrets to .agents/policies/scan-secrets
  from https://github.com/open-coder-ai/chock-catalog at …
Compiled. Run `chock sync --repo .` to activate commit-time enforcement.

$ chock add protect-main-branch
Added protect-main-branch to .agents/policies/protect-main-branch
  from https://github.com/open-coder-ai/chock-catalog at …
Compiled. Run `chock sync --repo .` to activate commit-time enforcement.

$ chock sync --repo .
Recompiled 2 policies

$ echo 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' > config.py && git add config.py && git commit -m "add config"
Potential secret detected in this change. Remove credentials and rotate any exposed keys. '# pragma: allowlist secret' on the same line marks a documented test fixture; in the agent (tool use, the turn's end) it counts only when that exact line is already committed in HEAD, so an agent asks a person rather than writing the pragma itself.
  - config.py: content pattern
# exit 1
```

Remove the key and the same commit passes. Then, on `main`:

```console
$ git commit --allow-empty -m notes
Direct commits/pushes to a protected branch (main|master) are blocked. Create a feature branch and open a pull request.
  - main
# exit 1
```

The protected branches in that message are not hard-coded — they are the ones the gate is
actually enforcing, read from `chock.defaults.protected_branches`. A block message that names
a different set from the gate is how an adopter learns to distrust the tool.

<img alt="Four commands take a repository from no enforcement to a blocked commit" src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/adoption.svg">

---

## How it works

One folder per policy. `manifest.yaml` declares identity and either a gate or rule text;
`chock sync` compiles that into git hooks, native pre-tool hooks, or ambient rule text,
whichever surfaces the agent you use actually supports:

<img alt="A policy folder compiles into git-hook, native pre-execution hook and ambient-rule surfaces, which reach different enforcement levels" src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/how-it-works.svg">

The same policy reaches different levels on different agents, and `coverage.json` records
every pair — `none` where no surface can carry it, rather than a silently missing row.

Gates run in **git** itself, so they hold no matter which agent, or human, is at the
keyboard — the whole argument for a hook over a prompt an agent can forget once the
instruction scrolls out of context. Fifteen adapters (`aider`, `antigravity`, `claude`,
`codex`, `copilot`, `cursor`, `devin`, `gemini`, `grok`, `junie`, `kimi-code`, `replit`,
`tabnine`, `vscode`, `windsurf`) are generated from one `AGENTS.md`, because the rules live in one place and the
adapters exist only to match filenames each agent looks for.

Every policy folder is yours: `cp -r base/scan-secrets <your-repo>/.agents/policies/` plus
`chock sync --repo .` produces output byte-identical to `chock add`, and nothing upstream
ever overwrites your copy. The full argument for gates over prompts, the complete adapter
list, and what editing your copy looks like are in
[docs/how-it-works.md](docs/how-it-works.md).

---

## This repo runs what it publishes

The catalog is a Chock adopter: `.agents/policies/` holds the subset of `base/` that governs
this repository, so it protects itself the same way it asks any open-source repo to, and the first commit after
adoption was rejected by `protect-main-branch`. That is not a flourish — a worked example
that is a repository cannot drift from the instructions the way a README snippet does, and
running it has already found four framework bugs no test caught. CI still keeps two things
apart: **what this repo runs** (the `base/` tier only — the compliance and agentic-security
packs stay uninstalled because, by their own doctrine, they only earn their place where they
apply) and **what this repo ships** (every published policy, staged into a throwaway repo the
way an adopter installs them). A catalog should publish more than it is bound by — the
full three-paragraph version, including which policy is installed-but-disabled here and
why, and the specific framework bugs this adoption already caught, is in
[docs/how-it-works.md](docs/how-it-works.md).

## Every policy is an Agent Plugin

Every `base/<id>/` folder is also a conformant [Agent Plugins 1.0.0](https://agent-plugins.org)
package — `plugin.json` plus `skills/<id>/SKILL.md`, both generated from `manifest.yaml` — so
any client implementing the spec can read these policies with no Chock installed at all. That
is a portability claim, not an enforcement one: the standard defines no hook mechanism, so a
policy read as a plugin is `advisory` regardless of its tier here, and real enforcement still
comes from `chock sync` or from the per-vendor plugin builds, each witnessed denying a
destructive command on a real install —
[claude](https://github.com/open-coder-ai/chock-claude-plugins) ·
[copilot](https://github.com/open-coder-ai/chock-copilot-plugins) ·
[cursor](https://github.com/open-coder-ai/chock-cursor-plugins) ·
[codex](https://github.com/open-coder-ai/chock-codex-plugins).

---

## Installing this is running code

A policy here is not inert data. A declarative policy compiles to a git hook that runs on every
commit in your repository; a policy shipping an `implementations/` guard becomes a guard script
consulted before your agent runs a command; `java-security`, `agentic-code-security` and
`no-a11y-regression` run their own program at commit and when the agent writes, and
`firecrawl-fallback-only` and `token-efficiency` run theirs before a matching tool call.
Either way `chock add` installs executable content over `git clone`. There is no signing
key — pin and verify when the catalog is not one you control:

```bash
chock add scan-secrets --ref <commit-sha> --verify-sha <sha256>
```

This catalog publishes no tags, so pin a commit SHA. `--ref` takes any ref the remote has;
`--verify-sha` refuses the install unless the fetched pack hashes to the value you name.

Two limits worth knowing before you rely on any of this: `git commit --no-verify` skips every
git hook, and git hooks are not cloned — a fresh clone enforces nothing until someone runs
`chock sync`. [SECURITY.md](SECURITY.md) has the rest.

---

## Contributing

Issues and PRs welcome, including "this policy is wrong" — an overstated policy is worse
here than a missing one. Every claim here is checked by CI rather than a reviewer's memory: a
policy claims only what it can do, and its evals are the argument for what its gate actually
blocks. Concrete first contributions:

| Contribution | Where to start |
| :--- | :--- |
| Found a bypass? Add the eval case that proves it | `evals/suite.yaml` in the policy's folder |
| Ship a new guardrail | `chock new policy <id>`, then the `policy-init` skill |
| Answer a `policy wanted` threat | [chock-threat-intel](https://github.com/open-coder-ai/chock-threat-intel) |
| Verify an agent's row with a live run | [agentseam](https://github.com/open-coder-ai/agentseam) |
| Pick up a labelled issue | [good first issues](https://github.com/open-coder-ai/chock-catalog/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) |

Every commit carries a DCO `Signed-off-by:` trailer (`git commit -s`). The full guide —
transcripts, DCO, review criteria — is in [CONTRIBUTING.md](CONTRIBUTING.md); run the same
loop CI does:

```bash
chock check && chock check --only evals
```

Looking for something specific to work on, or a place to ask a question first? The threat
ledger and Discussions link are in [CONTRIBUTING.md](CONTRIBUTING.md#good-first-contributions).
Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.

---

## Part of open-coder-ai

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/figures/family-dark.svg">
  <img alt="A layered diagram. agentseam is the foundation across the bottom; chock sits on it; chock-catalog feeds chock and generates the four plugin repositories; chock-threat-intel feeds the catalog; context-report runs as a verification arm beside all of them." src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/figures/family-light.svg" width="800">
</picture>

| | |
|---|---|
| [agentseam](https://github.com/open-coder-ai/agentseam) | the primitives — one handler API and a verified capability matrix across 16 agents |
| [chock](https://github.com/open-coder-ai/chock) | the compiler — one policy into git hooks, CI gates and native pre-tool hooks |
| [chock-catalog](https://github.com/open-coder-ai/chock-catalog) | the policies — 48, each labelled enforced or advisory, with replayed evals |
| [context-report](https://github.com/open-coder-ai/context-report) | the evidence — a signed report of whether an agent artifact actually works |
| [chock-threat-intel](https://github.com/open-coder-ai/chock-threat-intel) | the threat ledger the catalog's policies answer to |
| chock-{claude,cursor,copilot,codex}-plugins | the catalog, packaged for each agent's plugin format (generated) |
| chock-quickstart · chock-example | template repos: what `chock init` leaves behind, and a full adoption |

Apache-2.0 — see [LICENSE](LICENSE). Contributor Covenant
[Code of Conduct](CODE_OF_CONDUCT.md).
