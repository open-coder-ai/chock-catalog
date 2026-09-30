# Protect Commit Privacy

`protect-commit-privacy` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | commit-time guard script `protect-commit-privacy-commit-msg.py` |
| **Reaches** | `enforced-at-commit` — the script exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ambient-rule` |
| **Eval cases** | 35 total, 35 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Keeps the development conversation out of git history. Guard refuses `git commit` and `gh pr create|edit` whose message or body (inline -m/-b, -F/--file/--body-file, heredoc on -F -) holds a process-leak marker (session link, 'user asked', ...); commands behind cd, sh -c, sudo, env are read. A commit-msg hook applies the same markers to the recorded message. Narrow deny-list. No waiver: a legitimate phrase needs a person to remove it from MARKERS in the guard; an agent asks the person.

## What it solves

A threat that did not exist before agents wrote commits: process leakage through authorship. A human curates what goes into a commit message; an agent narrates by default -- who asked, what the plan was, which discussion decided it -- and on a public repo that narration is published forever, in a place nobody reviews for privacy. This policy was authored from a live incident: the catalog's own maintainer found agent-written messages carrying private decisions toward a public launch.

## How it works

A guard script, `implementations/protect-commit-privacy-commit-msg.py`, run by the git hook at every commit with no arguments. It reads the staged revision of each file from git and exits non-zero to refuse the commit.

The rule text ships alongside, so an agent reading its context knows the constraint before it stages the change rather than only after being refused:

```text
commit_message|pr_description: describe(change); never(narrate: conversation|plan|who_asked|user_quotes|session_refs|internal_doc_paths)
if(marker_hit|sensitive_context): ask_person before(commit); no_waiver(person removes phrase from MARKERS); never(edit MARKERS)  # history is published forever
```

## Which primitive it becomes

A **commit-time guard script**. `recompile` registers `implementations/protect-commit-privacy-commit-msg.py` under `.git/hooks/pre-commit.d/`, and the hook runs it at every commit (a commit-msg script gets git's message file as its one argument, any other none). The script reads the change from git itself and exits non-zero to refuse; the rule text compiles to `ambient-rule` beside it, so the agent knows the constraint before the commit is refused.

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
