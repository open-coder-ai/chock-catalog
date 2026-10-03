---
name: scan-secret-files
description: "Friction, not a security boundary: flags files that are secrets by name or content -- private keys and key stores, Google service-account/OAuth JSON, kubeconfig users, AWS, npm, PyPI, netrc, git, pgpass, docker, Composer, NuGet, Maven credentials, tfstate/tfvars, non-template .env, framework secret files, browser stores. Warns only (observe). Misses: renamed binary stores other than PKCS#12/JKS/DER, unlisted secret names, values split or encoded."
metadata:
  chock.artifact: hook
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Scan Secret Files

Friction, not a security boundary: flags files that are secrets by name or content -- private keys and key stores, Google service-account/OAuth JSON, kubeconfig users, AWS, npm, PyPI, netrc, git, pgpass, docker, Composer, NuGet, Maven credentials, tfstate/tfvars, non-template .env, framework secret files, browser stores. Warns only (observe). Misses: renamed binary stores other than PKCS#12/JKS/DER, unlisted secret names, values split or encoded.

```
on(commit|tool_use): warn(script) script=scan-secret-files-gate.py
This file is a secret, or holds one: a private key or key store, a cloud, registry or tool credential file, Terraform state, a dotenv file with live values, or a browser credential store. Keep it out of the repository: add it to .gitignore, load the value from the environment or a secret manager, and commit a template with placeholders (.env.example) instead. Rotate any credential that was written or pushed. There is no inline waiver; a person who has reviewed a fixture commits it from their own shell.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
