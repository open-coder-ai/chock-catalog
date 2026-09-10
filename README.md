<div align="center">

<img src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/logo.svg" alt="chock-catalog: the policy catalog for chock -- policies you can adopt, graded by what they actually enforce. The mark is a stack of policy cards, the top one carrying the node that marks an enforcing policy." width="110">

<h1>chock-catalog</h1>

<p><strong>Policies that stop your coding agent from doing the thing you would have caught in review.</strong></p>

<p>
<img alt="39 policies" src="https://img.shields.io/badge/policies-40-blue">
<img alt="18 enforced" src="https://img.shields.io/badge/enforced-18-brightgreen">
<img alt="22 advisory" src="https://img.shields.io/badge/advisory-22-orange">
<img alt="agents" src="https://img.shields.io/badge/agents-13-8957e5">
<a href="https://github.com/open-coder-ai/chock-catalog/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/open-coder-ai/chock-catalog/actions/workflows/ci.yml/badge.svg"></a>
<img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-lightgrey">
<a href="https://scorecard.dev/viewer/?uri=github.com/open-coder-ai/chock-catalog"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/open-coder-ai/chock-catalog/badge"></a>
<a href="CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
</p>

<p>
<a href="#the-policies">The policies</a> ·
<a href="#it-actually-blocks-the-commit">See it block</a> ·
<a href="#how-it-works">How it works</a> ·
<a href="#contributing">Contributing</a> ·
<a href="https://github.com/open-coder-ai/chock">the framework →</a>
</p>

<img src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/demo.gif" width="760" alt="Terminal session: chock add scan-secrets and protect-main-branch are installed, a commit containing an AWS key is blocked, the same commit passes once the key is read from the environment instead, and a commit straight to main is blocked next.">

</div>

Your agent is fast, tireless, and occasionally commits an AWS key. Prompting it not to works
until the context fills up. This is the part that does not depend on the model paying
attention.

---

## The policies

**A rule an agent reads is advice. A hook that exits non-zero is a control.** Both belong in
a repo, and the difference has to be visible, because the failure mode of governance tooling
is that everyone believes it is doing more than it is. So every policy here is labelled with
what it actually reaches — stated up front rather than in the appendix, because 22 of the 39
are advisory, and that is the number most catalogs would round up:

| | What it means | How many |
| :--- | :--- | ---: |
| `enforced-at-commit` | the command exits non-zero, the commit does not happen | 10 |
| `in-agent` | the tool call is refused before it runs, if the hook itself runs | 8 |
| `advisory` | text an agent reads and may or may not follow | 22 |

<img alt="40 policies: 10 enforced-at-commit, 8 in-agent, 22 advisory" src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/assets/coverage-matrix.svg">

The same distribution, in the shared open-coder-ai figure language and readable in either
theme:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/figures/enforcement-dark.svg">
  <img alt="Of 39 chock-catalog policies, 9 are enforced at commit and 8 more are enforced in-agent, for 17 enforced overall -- 22, more than half, are advisory only, read by the agent but backed by no mechanism." src="https://raw.githubusercontent.com/open-coder-ai/chock-catalog/main/docs/figures/enforcement-light.svg" width="760">
</picture>

Advisory evals report as *skipped*, never as *passing*, because there is nothing to replay.

**Enforced at commit** — declarative gates, verified by replaying their own gate against a
throwaway repo on every push.

| Policy | Blocks | Evals |
| :--- | :--- | ---: |
| [`protect-main-branch`](docs/protect-main-branch/) | commits and pushes to `main`/`master` | 4/4 |
| [`scan-secrets`](docs/scan-secrets/) | credentials in staged changes | 20/20 |
| [`verify-dependency-exists`](docs/verify-dependency-exists/) | packages absent from your allowlist | 5/5 |
| [`block-invisible-unicode`](docs/block-invisible-unicode/) | bidi-override and tag-block Unicode in staged changes -- Trojan Source and instructions hidden from reviewers but legible to agents | 8/8 |
| [`block-wildcard-agent-permissions`](docs/block-wildcard-agent-permissions/) | committed everything-grants -- bare-wildcard shell grants and allow-everything tool lists -- that hand an agent unlimited tool authority | 11/11 |
| [`pin-github-actions`](docs/pin-github-actions/) | a workflow that references a third-party GitHub Action by a movable tag or branch instead of a full commit SHA -- so a re-tagged or compromised release can't change what CI runs; SHA pins and local actions pass | 9/9 |
| [`block-wildcard-iam`](docs/block-wildcard-iam/) | wildcard Action or Resource in an IAM policy document, `AdministratorAccess` attachment, GCP `roles/owner` or `roles/editor`, and Terraform wildcard action or resource lists -- the mechanizable slice of ASI03 | 6/6 |
| [`block-unpinned-agent-components`](docs/block-unpinned-agent-components/) | agent components pulled at an unpinned version -- `npx`/`uvx`/`bunx` launches at `@latest` (the standard MCP server idiom), quoted `"@latest"` in agent config, and `:latest` image tags -- the mechanizable slice of ASI04 | 6/6 |
| [`block-unsafe-code-execution`](docs/block-unsafe-code-execution/) | bare `eval`/`exec`, shell-mode subprocess calls, `os.system`, `pickle`/`marshal` loads, `yaml.load` without `SafeLoader`, `execSync` and `new Function` -- a best-effort line scan over the mechanizable slice of ASI05 | 7/7 |
| [`no-a11y-regression`](docs/no-a11y-regression/) | a change that destroys an accessibility assertion the previous revision carried -- a description replaced by `alt=""`, or a flagged element deleted rather than fixed; neither produces a violation, so both pass every violation report | 0/13 |

**Enforced before the tool runs** — guard scripts consulted before the agent executes a
command, natively wired in Claude Code, Cursor, Copilot CLI and VS Code (and, via the
codex plugin format, Codex after its per-hook trust review).

| Policy | Refuses | Evals |
| :--- | :--- | ---: |
| [`block-destructive-commands`](docs/block-destructive-commands/) | `rm -rf /`, force push, hard reset, `terraform destroy`, `dropdb`, `helm uninstall`, `docker volume rm`, `aws s3 rm --recursive`, `gcloud … delete` | 42/42 |
| [`block-no-verify`](docs/block-no-verify/) | `--no-verify`, which bypasses every gate above | 17/17 |
| [`protect-agent-config`](docs/protect-agent-config/) | shell edits to the agent's own instruction, permission and enforcement files (now including the policy guard sources themselves) -- self-modification refused up front | 24/24 |
| [`protect-commit-privacy`](docs/protect-commit-privacy/) | commit messages and `gh pr create`/`edit` bodies that narrate the development conversation (or leak a session link) instead of describing the change — a leak class that only exists once an agent authors the commit | 20/20 |
| [`block-curl-pipe-sh`](docs/block-curl-pipe-sh/) | piping a network download into a shell or script interpreter — `curl … \| sh`, `wget … \| bash`, `curl … \| python`, `bash -c "$(curl …)"`, `iwr … \| iex` — while download-to-file and pipes into non-interpreter tools stay allowed | 27/27 |
| [`protect-ci-workflows`](docs/protect-ci-workflows/) | shell writes to the CI/CD config that gates a change — `.github/workflows/`, `.github/actions/`, `.github/dependabot.yml` — so an agent can't delete or loosen the checks reviewing its own work; reads and `chock sync` pass | 19/19 |
| [`block-unapproved-egress`](docs/block-unapproved-egress/) | a network client that uploads data — `curl -d`/`-F`/`--upload-file`, `-X POST`, `wget --post-file`, `Invoke-WebRequest -Method POST` — to a host outside the egress allowlist; fetch-only traffic and `pip install` pass. A tool-time floor, not a network sandbox | 32/32 |
| [`verify-mcp-allowlist`](docs/verify-mcp-allowlist/) | a shell write to `.mcp.json` adding an MCP server not on the allowlist, or changing an allowed server's command/args/url to point elsewhere (including one renamed to an allowed name) — the allowlist ships inside the guard script itself, protected the same way as any other policy's guard source; a matching entry passes without a human approval each time | 15/15 |

<details>
<summary>22 advisory policies — expand</summary>

**Advisory** — rule text compiled into agent context. No mechanism, no executed evals.

[`agent-discipline`](docs/agent-discipline/) · [`code-safety`](docs/code-safety/) ·
[`context-hygiene`](docs/context-hygiene/) · [`chock-mise`](docs/chock-mise/) ·
[`firecrawl-fallback-only`](docs/firecrawl-fallback-only/) ·
[`git-safety`](docs/git-safety/) ·
[`injection-defense`](docs/injection-defense/) ·
[`memory-discipline`](docs/memory-discipline/) · [`token-efficiency`](docs/token-efficiency/)

</details>

<details>
<summary>3 compliance policies — expand</summary>

**Compliance** — jurisdiction-specific, in `compliance/` rather than `base/`. Everything
above applies to any repo; these only earn their place if the regulation reaches you.

| Policy | Covers | In force |
| :--- | :--- | :--- |
| [`eu-ai-act-transparency`](docs/eu-ai-act-transparency/) | EU AI Act Art 50 — AI disclosure, machine-readable marking of synthetic output, deepfake labelling | now |
| [`eu-ai-act-prohibited-practices`](docs/eu-ai-act-prohibited-practices/) | Art 5 — social scoring, face scraping, workplace emotion inference, NCII/CSAM | now |
| [`eu-ai-act-high-risk-triage`](docs/eu-ai-act-high-risk-triage/) | Annex III domains, Articles 9–15 | 2027-12-02 |

Advisory, like everything else with no mechanism. Regulatory scoping is judgement, and a
keyword gate here would block on `emotion_recognition` in a comment.

</details>

<details>
<summary>OWASP ASI01–10 coverage — expand</summary>

**Agentic security** — the OWASP Top 10 for Agentic Applications (2026), in
`agentic-security/`. One policy per ASI category. These govern the agentic system you are
*building*; everything above governs the agent doing the building. They only earn their
place if your repo ships agents that plan, call tools, persist memory, or coordinate.

| Policy | Guards against |
| :--- | :--- |
| [`owasp-asi01-agent-goal-hijack`](docs/owasp-asi01-agent-goal-hijack/) | untrusted content redirecting the agent's goal or tool scope |
| [`owasp-asi02-tool-misuse`](docs/owasp-asi02-tool-misuse/) | excess agency, parameter abuse, unsafe tool chains |
| [`owasp-asi03-identity-privilege-abuse`](docs/owasp-asi03-identity-privilege-abuse/) | borrowed credentials, shared accounts, long-lived broad tokens |
| [`owasp-asi04-agentic-supply-chain`](docs/owasp-asi04-agentic-supply-chain/) | unverified MCP servers, frameworks, runtime-discovered tools |
| [`owasp-asi05-unexpected-code-execution`](docs/owasp-asi05-unexpected-code-execution/) | generated code escaping its sandbox; untrusted strings reaching an interpreter |
| [`owasp-asi06-memory-context-poisoning`](docs/owasp-asi06-memory-context-poisoning/) | poisoned durable memory steering later sessions |
| [`owasp-asi07-insecure-inter-agent-communication`](docs/owasp-asi07-insecure-inter-agent-communication/) | peer impersonation, tampering, replay, fake discovery |
| [`owasp-asi08-cascading-failures`](docs/owasp-asi08-cascading-failures/) | one agent's bad output propagating through downstream automation |
| [`owasp-asi09-human-agent-trust`](docs/owasp-asi09-human-agent-trust/) | approval surfaces the agent itself authors |
| [`owasp-asi10-rogue-agents`](docs/owasp-asi10-rogue-agents/) | drifted, compromised, or uninventoried agents |

Advisory, and for the same reason: whether a tool grant is "least agency" is a judgement
about your architecture, not a pattern a gate can match. Three of these deliberately overlap
`injection-defense`, `code-safety`, and `memory-discipline` — those govern your coding
agent's own session, these govern the product it writes.

Three ASI categories do have a slice a diff can literally show, and those slices get real
gates — narrow siblings named for exactly what they block, so the advisory policy never
claims an enforcement it does not have:

| Gate | Blocks | Slice of | Evals |
| :--- | :--- | :--- | ---: |
| [`block-unsafe-code-execution`](docs/block-unsafe-code-execution/) | bare `eval`/`exec`, `shell=True`, unsafe deserialization | ASI05 | 7/7 |
| [`block-wildcard-iam`](docs/block-wildcard-iam/) | `"Action": "*"`, `AdministratorAccess`, `roles/owner` | ASI03 | 6/6 |
| [`block-unpinned-agent-components`](docs/block-unpinned-agent-components/) | `npx -y server@latest`, `:latest` images | ASI04 | 6/6 |

The pattern is the same one `base/` uses: `code-safety` advises broadly while
`scan-secrets` blocks narrowly. The gate is not the rule promoted — it is the greppable
fraction, enforced honestly, with the judgement half still labelled advisory.

How the 10/10 claim above is re-derived on every build, and what `partial` versus `full`
actually means, is in [docs/coverage.md](docs/coverage.md).

</details>

Every policy has [its own page](docs/) — what it solves, how it works, which primitive it
becomes, and what is safe to change.

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

The next commit containing a credential exits non-zero instead of landing:

```console
$ echo 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' > config.py && git add config.py && git commit -m "add config"
Potential secret detected in this change. Remove credentials and rotate any exposed keys. At commit, add '# pragma: allowlist secret' on the same line only for documented test fixtures; the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.
  - config.py: content pattern
# exit 1
```

---

## It actually blocks the commit

This is the session the GIF above records — real output from a real repository, not written
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
Potential secret detected in this change. Remove credentials and rotate any exposed keys. At commit, add '# pragma: allowlist secret' on the same line only for documented test fixtures; the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.
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
every pair — `unsupported` where a surface can't carry it, rather than a silently missing row.

Gates run in **git** itself, so they hold no matter which agent, or human, is at the
keyboard — the whole argument for a hook over a prompt an agent can forget once the
instruction scrolls out of context. Thirteen adapters (`claude`, `copilot`, `cursor`,
`gemini`, `codex`, `aider`, `windsurf`, `devin`, `grok`, `kimi-code`, `replit`, `tabnine`,
`vscode`) are generated from one `AGENTS.md`, because the rules live in one place and the
adapters exist only to match filenames each agent looks for.

Every policy folder is yours: `cp -r base/scan-secrets <your-repo>/.agents/policies/` plus
`chock sync --repo .` produces output byte-identical to `chock add`, and nothing upstream
ever overwrites your copy. The full argument for gates over prompts, the complete adapter
list, and what editing your copy looks like are in
[docs/how-it-works.md](docs/how-it-works.md).

---

## This repo runs what it publishes

The catalog is a Chock adopter: `.agents/policies/` holds every `base/` policy, so it
protects itself the same way it asks any open-source repo to, and the first commit after
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

A policy here is not inert data: its `implementations/*.sh` becomes a git hook that runs on
every commit and a guard consulted before your agent executes a command, so `chock add`
installs executable content over `git clone`. There is no signing key — pin and verify when
the catalog is not one you control:

```bash
chock add scan-secrets --ref v1.0.0 --verify-sha <sha256>
```

Two limits worth knowing before you rely on any of this: `git commit --no-verify` skips every
git hook, and git hooks are not cloned — a fresh clone enforces nothing until someone runs
`chock sync`. [SECURITY.md](SECURITY.md) has the rest.

---

## Contributing

Issues and PRs welcome, including "this policy is wrong" — an overstated policy is worse
here than a missing one. Every claim here is checked by CI rather than a reviewer's memory: a
policy claims only what it can do, and its evals are the argument for what its gate actually
blocks. Start with [a good first
issue](https://github.com/open-coder-ai/chock-catalog/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22),
or read the full guide — transcripts, DCO, review criteria — in
[CONTRIBUTING.md](CONTRIBUTING.md) and run the same loop CI does:

```bash
chock check && chock check --only evals
```

Looking for something specific to work on, or a place to ask a question first? The threat
ledger and Discussions link are in [CONTRIBUTING.md](CONTRIBUTING.md#good-first-contributions).

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
| [chock-catalog](https://github.com/open-coder-ai/chock-catalog) | the policies — 39, each labelled enforced or advisory, with replayed evals |
| [context-report](https://github.com/open-coder-ai/context-report) | the evidence — a signed report of whether an agent artifact actually works |
| [chock-threat-intel](https://github.com/open-coder-ai/chock-threat-intel) | the threat ledger the catalog's policies answer to |
| chock-{claude,cursor,copilot,codex}-plugins | the catalog, packaged for each agent's plugin format (generated) |
| chock-quickstart · chock-example | template repos: what `chock init` leaves behind, and a full adoption |

Apache-2.0 — see [LICENSE](LICENSE). Contributor Covenant
[Code of Conduct](CODE_OF_CONDUCT.md).
