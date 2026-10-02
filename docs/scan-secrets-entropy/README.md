# Scan Secrets Entropy

`scan-secrets-entropy` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | warn-only `script` gate |
| **Reaches** | `advisory` — the gate runs and prints its findings; it never refuses |
| **Compiles to** | `git-hook`, `ci-gate`, `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 25 total, 25 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: flags secrets scan-secrets misses -- high-entropy values (16-150 chars) assigned to secret-like keys, GitHub/npm tokens whose checksum verifies, Stripe test keys, Slack and AWS key-id shapes, Luhn-valid cards. Warns only (observe). Misses: values split across lines, over 150 characters, cut short by # or & when unquoted, under other key names, written like code (a.b(), ALL_CAPS, words, URLs, paths), wrapped in a call, parentheses or concatenation, or in XML.

## What it solves

scan-secrets refuses vendor prefixes and a fixed set of assignment patterns, so a random credential under a key it does not spell, a Stripe test key, a Slack app token or an AWS bearer-token id slips past it. This gate judges every value assigned to a secret-like key by its entropy, skipping references, digests, UUIDs, placeholders and values written as code or paths, and checks vendor tokens by their built-in checksum or issued shape and card numbers by Luhn. Values are never printed; a finding's key is a hash. It warns while its false-positive rate is measured, then asks.

## How it works

A `script` gate runs on `commit` and `tool_use` and only warns: its action is `warn`, so it prints its findings and never refuses. It does not enforce anything, so the policy counts as advisory.

On a finding it prints:

> Possible secret: a high-entropy value assigned to a secret-like key, a vendor token whose structure checks out, or a card number. Move it to an environment variable or a secret store and reference it; rotate it if it was ever real. A person who has checked a test value keeps it with 'pragma: allowlist secret' on the same line (a person's commit, push or CI honours it; in the agent only a line already in HEAD counts). An agent asks a person; it never writes the pragma.

## Which primitive it becomes

A **warn-only gate**. `recompile` writes it under `.chock/compiled/scan-secrets-entropy/` for each surface its `on` names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but its exit never refuses a commit or a write.

## Installing it

```bash
chock add scan-secrets-entropy
chock sync --repo .
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
