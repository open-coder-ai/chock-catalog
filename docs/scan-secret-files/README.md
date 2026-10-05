# Scan Secret Files

`scan-secret-files` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 25 total, 25 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Friction, not a security boundary: flags files that are secrets by name or content -- private keys and key stores, Google service-account/OAuth JSON, kubeconfig users, AWS, npm, PyPI, netrc, git, pgpass, docker, Composer, NuGet, Maven credentials, tfstate/tfvars, non-template .env, framework secret files, browser stores. Blocks; encrypted keys, notebook outputs and test, fixture, example, doc, lock and eval paths ask. Misses: renamed binary stores other than PKCS#12/JKS/DER, unlisted secret names, values split or encoded.

## What it solves

scan-secrets reads one line at a time, so it cannot tell that a whole file is a credential. A kubeconfig with an inline token, a service-account JSON, Terraform state, an `.npmrc` or `.git-credentials`, a PKCS#12 store or a browser cookie database leaks the moment it is committed, and renaming it does not change what it is. This script judges every file a change writes, by name and by shape (kubeconfig, JSON and INI shapes, PEM and PuTTY key blocks, DER and keystore headers), and flags the ones that are secrets. Templates (`.env.example`) stay allowed. It warns while its false-positive rate is measured, then blocks.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> This file is a secret, or holds one: a private key or key store, a cloud, registry or tool credential file, Terraform state, a dotenv file with live values, or a browser credential store. Keep it out of the repository: add it to .gitignore, load the value from the environment or a secret manager, and commit a template with placeholders (.env.example) instead. Rotate any credential that was written or pushed. There is no inline waiver; a person who has reviewed a fixture commits it from their own shell.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/scan-secret-files/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add scan-secret-files
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/scan-secret-files  <your-repo>/.agents/policies/scan-secret-files
cd <your-repo> && chock sync --repo .
```

## Customising it

The name tables and shapes are constants in `implementations/sbf_*.py`. Test, fixture, example, doc, lock and eval paths ask instead of refusing. There is no inline waiver (binary and JSON files cannot carry one); a person who has reviewed a fixture commits it from their own shell with `CHOCK_ALLOW=scan-secret-files`. Not caught: a renamed binary key store other than PKCS#12, JKS/JCEKS and DER keys (BKS, KeePass, GnuPG keyrings are not judged at all), and an encrypted DER PKCS#8 key; YAML over the scanner's 1 MiB limit (a file with a `kind: Config` key it cannot read is still flagged); JSON this reader cannot parse is flagged only when it holds a credential file's keys; keys and values split across lines or encoded (UTF-16, base64), tfvars heredocs and Maven CDATA passwords; `.env` and tfvars keys that are not secret-like names, and low-entropy values that are paths or plain URLs (or sit under a `_FILE`, `_PATH`, `_NAME` or `_URL` key); a value holding a template word (example, changeme); `.pgpass` under another name, a renamed netrc that opens with a comment, a renamed git credential store holding any other line; `env.production` (no leading dot); `.yarnrc.yml`, `.gem/credentials`, `.s3cfg`, `.my.cnf`, `.htpasswd`, IDE data sources; notebook widget state and metadata. A key block missing its END line and re-wrapped under 40 characters per line, or a key interleaved with padding lines, is missed (neither loads as a key); random-looking text between key armor lines (a 32-character ID, an alphabet placeholder) is read as key bytes. A Java store with no key-protector OID asks (a truststore, often committed on purpose); PGP private keys always refuse. When one run holds both a refusal and an ask, the script exits with the refusal even if only the ask is new. Credentials in URIs, inline CLI passwords and high-entropy values are scan-secrets' and the entropy tier's.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals scan-secret-files
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/scan-secret-files/`](../../base/scan-secret-files/) · [all policies](../README.md)
