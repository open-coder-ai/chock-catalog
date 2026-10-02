# Scan Secrets Entropy

`scan-secrets-entropy` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 25 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: flags secrets scan-secrets' patterns miss -- high-entropy values of 16-150 characters assigned to secret-like keys, GitHub and npm tokens whose checksum verifies, Stripe test keys, Slack and AWS key-id shapes, Luhn-valid card numbers. Warns only (observe). Misses: values split across lines, over 150 characters, cut short by # or & when unquoted, under other key names, or written like code (a.b(), ALL_CAPS, word names, URLs, paths).

## What it solves

scan-secrets refuses vendor prefixes and a fixed set of assignment patterns, so a random credential under a key it does not spell, a Stripe test key, a Slack app token or an AWS bearer-token id slips past it. This gate judges every value assigned to a secret-like key by its entropy, skipping references, digests, UUIDs, placeholders and values written as code or paths, and checks vendor tokens by their built-in checksum or issued shape and card numbers by Luhn. Values are never printed; a finding's key is a hash. It warns while its false-positive rate is measured, then asks.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text

```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/scan-secrets-entropy/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

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
