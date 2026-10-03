---
name: block-secret-store-reads
description: "Best-effort guard against an agent reading credentials from the shell: cat, grep, sed, cp, tar, base64, source or < on ~/.ssh (not .pub), ~/.aws, ~/.npmrc, ~/.netrc, ~/.kube, ~/.gnupg, agent CLI dirs, browser login DBs, wallets, .env (not .env.example), *.tfstate; interpreter one-liners naming them; gh auth token, aws sts get-session-token, git credential fill. Asks on env/printenv dumps. Misses: scripts, unresolved variables, xargs lists, $(...) results."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Block Secret Store Reads

Best-effort guard against an agent reading credentials from the shell: cat, grep, sed, cp, tar, base64, source or < on ~/.ssh (not .pub), ~/.aws, ~/.npmrc, ~/.netrc, ~/.kube, ~/.gnupg, agent CLI dirs, browser login DBs, wallets, .env (not .env.example), *.tfstate; interpreter one-liners naming them; gh auth token, aws sts get-session-token, git credential fill. Asks on env/printenv dumps. Misses: scripts, unresolved variables, xargs lists, $(...) results.

```
never(read|print): credential_stores(~/.ssh(not_*.pub)|~/.aws|~/.npmrc|~/.netrc|~/.kube|~/.gnupg|agent_cli_dirs|browser_dbs|wallets|.env(not_.env.example)|*.tfstate)|tokens(gh_auth_token|aws_sts|git_credential_fill), via(cat|grep|sed|cp|tar|base64|source|<|interpreter)
ask: env|printenv|set|export_-p  # dumps every secret; if(value_needed): ask_person_for_that_value
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs. See https://github.com/open-coder-ai/chock
