# Agent Devenv Autoexec

`agent-devenv-autoexec` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | warns — warns on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | warn-only `script` gate |
| **Reaches** | `advisory` — the gate runs and prints its findings; it never refuses |
| **Compiles to** | `git-hook`, `ci-gate`, `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 50 total, 50 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns only (observe): flags files that make a dev tool run code on open, clone or shell entry -- agent hooks, helpers, env/BASE_URL overrides, auto-approve; VS Code folderOpen tasks, trust off, repo executables; devcontainer initializeCommand; .envrc, mise, husky, lefthook, pre-commit; gitconfig exec keys, gitattributes drivers, unsafe .gitmodules. Commit, agent write, turn's end; additions only; unreadable configs refused. Friction: misses interpreted code and unlisted files.

## What it solves

Files that make a developer tool run code with nobody pressing run: an agent hook or credential helper, an endpoint override that sends the agent's key elsewhere, a task that runs when the folder opens, a dev container command that runs on the host, a shell-entry or git hook file, a git config key that runs a program. An agent prompt-injected into writing one of these gets code execution on the next open, clone or checkout.

## How it works

A `script` gate runs on `commit` and `tool_use` and only warns: its action is `warn`, so it prints its findings and never refuses. It does not enforce anything, so the policy counts as advisory.

On a finding it prints:

> A file that a developer tool runs on its own (an agent hook or helper, an environment override, an auto-approval, a task that runs on folder open, a dev container command, a shell-entry or git hook file, a git config that runs a program) was added or changed, or such a config cannot be read. Remove it, or ask a person to review it. A reviewed line may carry 'chock: allow <rule-id>' where the file has comments; a person adds it in their own commit. In the agent a waiver counts only for a line already committed in HEAD, so an agent asks the person rather than writing it.

The rule text ships alongside, in the agent's ambient context:

```text
devenv_autoexec(agent hooks|helpers|env overrides|auto-approve|folderOpen tasks|trust off|devcontainer lifecycle|.envrc|mise|git hooks|gitconfig exec|gitattributes drivers|.gitmodules): changed by people only
never(add): hook|task|helper|env override|auto-approval; observe: warns at commit+tool_use, enforce later
```

## Which primitive it becomes

A **warn-only gate**. `recompile` writes it under `.chock/compiled/agent-devenv-autoexec/` for each surface its `on` names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but its exit never refuses a commit or a write.

## Installing it

```bash
chock add agent-devenv-autoexec
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/agent-devenv-autoexec  <your-repo>/.agents/policies/agent-devenv-autoexec
cd <your-repo> && chock sync --repo .
```

## Customising it

It ships at action warn (observe): it reports and never refuses. Measure what it reports with `chock check --history`, then move `hook.gate.action` to block. A reviewed line in a file that has comments may carry `chock: allow <rule-id>`, added by a person.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals agent-devenv-autoexec
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/agent-devenv-autoexec/`](../../base/agent-devenv-autoexec/) · [all policies](../README.md)
