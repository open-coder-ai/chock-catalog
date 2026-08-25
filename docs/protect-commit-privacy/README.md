# Protect Commit Privacy

`protect-commit-privacy` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `protect-commit-privacy.sh` |
| **Reaches** | `enforced` once `chock sync` has run — the tool call is refused before it runs |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 14 total, 14 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Keep the development conversation out of git history. Agent-authored commits narrate by default -- who asked for what, which discussion decided it, what the plan was -- and on a public repo that narration is published forever. The guard refuses git commit commands whose message (inline -m/--message or the file behind -F/--file) contains process-leak markers; the rule tells the agent to describe the change, not the conversation, and to propose sensitive messages to the human before committing. Best-effort: markers are a narrow deny-list, and a message the human explicitly approves can say anything -- edit the marker list in the guard, the content is yours.

## What it solves

A threat that did not exist before agents wrote commits: process leakage through authorship. A human curates what goes into a commit message; an agent narrates by default -- who asked, what the plan was, which discussion decided it -- and on a public repo that narration is published forever, in a place nobody reviews for privacy. This policy was authored from a live incident: the catalog's own maintainer found agent-written messages carrying private decisions toward a public launch.

## How it works

A guard script, `implementations/protect-commit-privacy.sh`, run before the agent executes a Bash command. It tokenizes the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```
commit_message|pr_description: describe(change); never(narrate: conversation|plan|who_asked|user_quotes|session_refs|internal_doc_paths)
if(sensitive_context): propose_message_to_human; await(approval) before(commit)  # history is published forever
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/protect-commit-privacy/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add protect-commit-privacy
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/protect-commit-privacy  <your-repo>/.agents/policies/protect-commit-privacy
cd <your-repo> && chock sync --repo .
```

## Customising it

The MARKERS list in the guard is the whole policy, and it is deliberately narrow -- phrases that describe the conversation, never single words like "user" that appear in honest messages about user-facing behaviour. Add your organisation's own tells (ticket-system phrases, internal codenames, private doc paths). If a marker keeps blocking legitimate messages, remove it: a guard that cannot be satisfied gets disabled within a week, and the rule half of this policy still does its work.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals protect-commit-privacy
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/protect-commit-privacy/`](../../base/protect-commit-privacy/) · [all policies](../README.md)
