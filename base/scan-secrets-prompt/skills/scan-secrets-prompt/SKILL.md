---
name: scan-secrets-prompt
description: "Refuses a prompt that holds a credential, before the model reads it: vendor tokens (AWS, GitHub, GitLab, Slack, OpenAI, Anthropic, HF, ...), private-key blocks with a body, JWTs, URI logins, Authorization literals. Only shapes that are a credential wherever they sit; no name-based rule, so code that mentions a password passes. Allows AWS example keys, masked or truncated keys and variable names. Misses: a bare password, a split or encoded value, a vendor shape not listed. No waiver applies."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Scan Secrets in Prompts

Refuses a prompt that holds a credential, before the model reads it: vendor tokens (AWS, GitHub, GitLab, Slack, OpenAI, Anthropic, HF, ...), private-key blocks with a body, JWTs, URI logins, Authorization literals. Only shapes that are a credential wherever they sit; no name-based rule, so code that mentions a password passes. Allows AWS example keys, masked or truncated keys and variable names. Misses: a bare password, a split or encoded value, a vendor shape not listed. No waiver applies.

```
on(prompt_submit): block(content_regex) content_pattern(regex)
A credential was found in this prompt, so it was not sent. Remove it and submit again; if it was a real credential, rotate it, because it may already sit in a terminal history or a log.
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
