# Agent Devenv Autoexec

`agent-devenv-autoexec` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 50 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns only (observe): flags files that make a dev tool run code on open, clone or shell entry -- agent hooks, helpers, env/BASE_URL overrides, auto-approve; VS Code folderOpen tasks, trust off, repo executables; devcontainer initializeCommand; .envrc, mise, husky, lefthook, pre-commit; gitconfig exec keys, gitattributes drivers, unsafe .gitmodules. Commit, agent write, turn's end; additions only; unreadable configs refused. Friction: misses interpreted code and unlisted files.

## What it solves

Files that make a developer tool run code with nobody pressing run: an agent hook or credential helper, an endpoint override that sends the agent's key elsewhere, a task that runs when the folder opens, a dev container command that runs on the host, a shell-entry or git hook file, a git config key that runs a program. An agent prompt-injected into writing one of these gets code execution on the next open, clone or checkout.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
devenv_autoexec(agent hooks|helpers|env overrides|auto-approve|folderOpen tasks|trust off|devcontainer lifecycle|.envrc|mise|git hooks|gitconfig exec|gitattributes drivers|.gitmodules): changed by people only
never(add): hook|task|helper|env override|auto-approval; observe: warns at commit+tool_use, enforce later
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/agent-devenv-autoexec/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

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
