---
name: protect-commit-privacy
description: "Keeps the development conversation out of git history. Guard refuses `git commit` and `gh pr create|edit` whose message or body (inline -m/-b, -F/--file/--body-file, heredoc on -F -) holds a process-leak marker (session link, 'user asked', ...); commands behind cd, sh -c, sudo, env are read. A commit-msg hook applies the same markers to the recorded message. Narrow deny-list. No waiver: a legitimate phrase needs a person to remove it from MARKERS in the guard; an agent asks the person."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Protect Commit Privacy

Keeps the development conversation out of git history. Guard refuses `git commit` and `gh pr create|edit` whose message or body (inline -m/-b, -F/--file/--body-file, heredoc on -F -) holds a process-leak marker (session link, 'user asked', ...); commands behind cd, sh -c, sudo, env are read. A commit-msg hook applies the same markers to the recorded message. Narrow deny-list. No waiver: a legitimate phrase needs a person to remove it from MARKERS in the guard; an agent asks the person.

```
commit_message|pr_description: describe(change); never(narrate: conversation|plan|who_asked|user_quotes|session_refs|internal_doc_paths)
if(marker_hit|sensitive_context): ask_person before(commit); no_waiver(person removes phrase from MARKERS); never(edit MARKERS)  # history is published forever
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` can refuse an agent's shell command before it runs and a change at commit-msg. See https://github.com/open-coder-ai/chock
