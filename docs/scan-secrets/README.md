# Scan Secrets

`scan-secrets` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 40 total, 40 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks credentials: vendor tokens (AWS, GitHub, GitLab, Slack, OpenAI, HF, ...), JWTs, private-key and PGP blocks, named key/token/secret/password values (JSON, YAML, env, HCL, code), URI creds, Authorization literals, CLI password flags; files by path (.env*, keys). Misses: split or encoded values, quoted values with spaces, unlisted names, reference- or placeholder-like values. Runs: commit, agent write, turn end. Pragma same line; agent: only if in HEAD; MCP gateway: never.

## What it solves

Credentials reaching history, where deleting them does not remove them. Every key that lands has to be rotated, and rotation is the expensive part.

## How it works

A declarative `content_regex` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `forbidden_path_regex`
- `scan`

On a match it prints:

> Potential secret detected in this change. Remove credentials and rotate any exposed keys. '# pragma: allowlist secret' on the same line marks a documented test fixture; in the agent (tool use, the turn's end) it counts only when that exact line is already committed in HEAD, so an agent asks a person rather than writing the pragma itself.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/scan-secrets/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add scan-secrets
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/scan-secrets  <your-repo>/.agents/policies/scan-secrets
cd <your-repo> && chock sync --repo .
```

## Customising it

`params.content_pattern` is one regex and adding your own token formats is the main thing to do here -- internal key prefixes are exactly what a generic scanner misses. `params.forbidden_path_regex` covers file types; `params.allowlist_pragma` sets the inline escape for documented fixtures.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals scan-secrets
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/scan-secrets/`](../../base/scan-secrets/) · [all policies](../README.md)
