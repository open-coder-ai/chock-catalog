# Scan Secrets Entropy

`scan-secrets-entropy` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | asks — asks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 25 total, 25 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: asks a person before a write adds secrets scan-secrets misses -- high-entropy values (16-150 chars) by secret-like keys, GitHub/npm tokens with valid checksums, Stripe test keys, Slack/AWS key-id shapes, Luhn-valid cards. Asks a person (HP01 entropy is a heuristic, so it asks rather than blocks). Misses: values split across lines, over 150 chars, cut by # or & when unquoted, under other key names, written like code (a.b(), ALL_CAPS, words, URLs, paths), wrapped in a call, parens or concatenation, in XML, or padded with control characters.

## What it solves

scan-secrets refuses vendor prefixes and a fixed set of assignment patterns, so a random credential under a key it does not spell, a Stripe test key, a Slack app token or an AWS bearer-token id slips past it. This gate judges every value assigned to a secret-like key by its entropy, skipping references, digests, UUIDs, placeholders and values written as code or paths, and checks vendor tokens by their built-in checksum or issued shape and card numbers by Luhn. Values are never printed; a finding's key is a hash. It warns while its false-positive rate is measured, then asks.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `ask`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> Possible secret: a high-entropy value assigned to a secret-like key, a vendor token whose structure checks out, or a card number. Move it to an environment variable or a secret store and reference it; rotate it if it was ever real. A person who has checked a test value keeps it with 'pragma: allowlist secret' on the same line (a person's commit, push or CI honours it; in the agent only a line already in HEAD counts). An agent asks a person; it never writes the pragma.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/scan-secrets-entropy/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add scan-secrets-entropy
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/scan-secrets-entropy  <your-repo>/.agents/policies/scan-secrets-entropy
cd <your-repo> && chock sync --repo .
```

## Customising it

The thresholds and allow reasons are chock_scan's (`lib/chock_scan/entropy.py`, `keyword_values.py`, `checksums.py`; edit lib/, never the copy), the non-secret shapes are `implementations/entropyscan/shapes.py`. A person keeps a checked test value with `pragma: allowlist secret` on the line (a JSON file cannot carry it). In the agent a waiver counts only for a line already in HEAD.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals scan-secrets-entropy
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/scan-secrets-entropy/`](../../base/scan-secrets-entropy/) · [all policies](../README.md)
