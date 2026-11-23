# Scan Secrets in Prompts

`scan-secrets-prompt` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | advisory — text only in a plugin. Nothing in the plugin stops a violation. The plugin does not carry the enforcement the manifest declares |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | content_regex gate |
| **Reaches** | `best-effort` on a client that can refuse a prompt, once `chock sync` has run — the prompt is refused before the model reads it. Not witnessed live in any client yet |
| **Compiles to** | `prompt-submit`, `ambient-rule` |
| **Eval cases** | 17 total, 17 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Refuses a prompt that holds a credential, before the model reads it: vendor tokens (AWS, GitHub, GitLab, Slack, OpenAI, Anthropic, HF, ...), private-key blocks with a body, JWTs, URI logins, Authorization literals. Only shapes that are a credential wherever they sit; no name-based rule, so code that mentions a password passes. Allows AWS example keys, masked or truncated keys and variable names. Misses: a bare password, a split or encoded value, a vendor shape not listed. No waiver applies.

## What it solves

A credential pasted into a prompt: it reaches the model, the provider's logs and the client's history before any commit gate runs, and every such key has to be rotated.

## How it works

A declarative `content_regex` gate, evaluated on `prompt_submit`, action `block`.

Parameters, from `manifest.yaml`:

- `content_pattern`

On a match it prints:

> A credential was found in this prompt, so it was not sent. Remove it and submit again; if it was a real credential, rotate it, because it may already sit in a terminal history or a log.

## Which primitive it becomes

A **prompt-submit gate**. `recompile` writes `.chock/compiled/scan-secrets-prompt/prompt-submit/prompt-submit-gate.json`, and `install-hooks` wires it into each client's prompt hook that can refuse a prompt. The gate is declarative: the compiled JSON is the whole check. It judges the prompt text alone, so no waiver applies, and a refusal never repeats the prompt.

## Installing it

```bash
chock add scan-secrets-prompt
chock sync .
```

Or [Open in the chock.sh builder](https://chock.sh/coding/builder/#s=eyJzY2hlbWEiOjIsImNsaWVudCI6ImNsYXVkZS1jb2RlIiwiYnVuZGxlIjp7InZlcnNpb24iOiIxLjAuMCJ9LCJjYXRhbG9nIjp7InNvdXJjZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuLWNvZGVyLWFpL2Nob2NrLWNhdGFsb2ciLCJyZWYiOiI3YjM2ZGExYWRmZmVhZjBiMDEyNmUxYzQ1YzhmODdlZTAyMjhiNmU1In0sInBvbGljaWVzIjpbeyJmcm9tIjoiY2F0YWxvZyIsImlkIjoic2Nhbi1zZWNyZXRzLXByb21wdCIsInZlcnNpb24iOiIwLjAuMSIsInNoYTI1NiI6IjQ3YzNjM2I3MDUyN2E3NWI0YjBjYzdiZWI2ZDkzNzM2N2VhZmZmZTk3MTc0NjFmZWUzZDY5ZDgwMTIyYjgxYWYifV19): this policy preselected for Claude Code, one merged plugin, installed with `chock install --selection <code> --apply`.

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/scan-secrets-prompt  <your-repo>/.agents/policies/scan-secrets-prompt
cd <your-repo> && chock sync --repo .
```

## Customising it

`params.content_pattern` is one regex and holds only shapes that are a credential wherever they sit; add your own token formats there. A name-based rule (`password = ...`) belongs in scan-secrets, not here: it would refuse a person describing code. No waiver applies at a prompt.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals scan-secrets-prompt
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/scan-secrets-prompt/`](../../base/scan-secrets-prompt/) · [all policies](../README.md)
