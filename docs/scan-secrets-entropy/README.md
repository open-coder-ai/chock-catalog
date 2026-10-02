# Scan Secrets Entropy

`scan-secrets-entropy` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | guard script `scan-secrets-entropy-gate.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 23 total, 23 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: flags secrets scan-secrets' patterns miss -- high-entropy values of 16-150 characters assigned to secret-like keys, GitHub and npm tokens whose checksum verifies, Stripe test keys, Slack and AWS key-id shapes, Luhn-valid card numbers. Warns only (observe). Misses: values split across lines, over 150 characters, under other key names, or written like code (a.b(), ALL_CAPS, word names, URLs, paths).

## What it solves

scan-secrets refuses vendor prefixes and a fixed set of assignment patterns, so a random credential under a key it does not spell, a Stripe test key, a Slack app token or an AWS bearer-token id slips past it. This gate judges every value assigned to a secret-like key by its entropy, skipping references, digests, UUIDs, placeholders and values written as code or paths, and checks vendor tokens by their built-in checksum or issued shape and card numbers by Luhn. Values are never printed; a finding's key is a hash. It warns while its false-positive rate is measured, then asks.

## How it works

A guard script, `implementations/scan-secrets-entropy-gate.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text

```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/scan-secrets-entropy/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

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
