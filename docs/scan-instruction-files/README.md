# Scan Instruction Files

`scan-instruction-files` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 32 total, 31 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Asks a person before a change adds injection text to an agent instruction file (AGENTS.md, CLAUDE.md, GEMINI.md, Cursor/Windsurf/Cline/Roo/Kiro rules, Copilot instructions and prompts, SKILL.md, agent commands): rule overrides, secrecy, auto-approve, hook or review bypass, fetch-and-run, remote instructions, role swaps, fake system tags, removed guardrails. Refuses secret exfiltration and encoded payloads. Added text only; English phrases; friction, not a boundary.

## What it solves

An instruction file (AGENTS.md, CLAUDE.md, a rules folder, a skill, a prompt) is obeyed by every agent that opens the repository, so one poisoned line in it hijacks them all: overriding the rules, hiding work from a person, approving tools, skipping hooks, fetching and running code, or sending secrets away. This gate asks a person before a change adds such text, and refuses outright secret exfiltration and encoded payloads. Only what the change adds is judged, plus guardrail statements it deletes or weakens.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> This change adds text to an agent instruction file that an attacker would add: it overrides standing rules, hides work from a person, approves tools or skips hooks and review without one, downloads and runs code, follows remote instructions, recasts the agent's role, poses as a system message, removes a guardrail statement, sends a secret somewhere, or hides a command in an encoded blob. Write rules as prohibitions a person can review, and put setup steps in a reviewed script. A person keeps a reviewed line by committing from their own shell: CHOCK_ALLOW=scan-instruction-files for that one commit answers an ask, and 'chock: allow instruction-scan' on the line waives a refusal; an agent asks the person and never sets either.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/scan-instruction-files/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add scan-instruction-files
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/scan-instruction-files  <your-repo>/.agents/policies/scan-instruction-files
cd <your-repo> && chock sync --repo .
```

## Customising it

Ship it under `rollout: observe` in .chock/config.yaml first and read the gate log before enforcing. A person answers an ask by committing from their own shell with CHOCK_ALLOW=scan-instruction-files for that one commit, and waives a refusal with 'chock: allow instruction-scan' on the line. To stop judging the policy, list it under policies.disabled.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals scan-instruction-files
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/scan-instruction-files/`](../../base/scan-instruction-files/) · [all policies](../README.md)
