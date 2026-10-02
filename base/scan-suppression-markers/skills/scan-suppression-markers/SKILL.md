---
name: scan-suppression-markers
description: "Asks a person before a change adds a scanner suppression: inline ignore markers (bandit, gosec, ruff S codes, Sonar, Semgrep, ESLint security, Checkov, tfsec, Trivy, KICS, hadolint, cfn_nag, zizmor, gitleaks, detect-secrets, chock waivers, CodeQL, Java/C#/Rust security allows), scanner ignore files and skip keys, a CI scan set to pass on failure. Only added lines; prose skipped. Runs: commit, agent write, turn's end; CI annotates. Line-local, friction not a boundary."
metadata:
  chock.artifact: hook
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Scan Suppression Markers

Asks a person before a change adds a scanner suppression: inline ignore markers (bandit, gosec, ruff S codes, Sonar, Semgrep, ESLint security, Checkov, tfsec, Trivy, KICS, hadolint, cfn_nag, zizmor, gitleaks, detect-secrets, chock waivers, CodeQL, Java/C#/Rust security allows), scanner ignore files and skip keys, a CI scan set to pass on failure. Only added lines; prose skipped. Runs: commit, agent write, turn's end; CI annotates. Line-local, friction not a boundary.

```
on(commit|tool_use): ask(script) script=scan-suppression-markers-gate.py
This change adds a scanner suppression: an inline ignore marker, an ignore-file entry or skip key, or a CI security step told to pass when it fails. Fix what the scanner reports instead of silencing it. If the finding is a reviewed false positive, a person keeps the suppression by committing from their own shell with CHOCK_ALLOW=scan-suppression-markers for that one commit; an agent asks the person and never sets it.
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` asks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
