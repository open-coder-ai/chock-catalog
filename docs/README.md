# Policy reference

One page per published policy. Every page follows the same shape: what it is about, what it
solves, how it works, which primitive it becomes, how to install it, and how to customise it.

**Read the "Reaches" row first.** A policy that *enforces* is a control — the command exits
non-zero and the action does not happen. A policy that *advises* is text an agent reads and
may or may not follow. Both are useful. They are not interchangeable, and a catalog listing
makes them look alike.

## Enforced at commit

Declarative gates. The compiled `gate.json` is the whole check, so reviewing it reviews the
effect rather than the intent.

| Policy | Blocks | Evals |
| :--- | :--- | ---: |
| [protect-main-branch](protect-main-branch/) | commits and pushes to `main`/`master` | 4/4 |
| [scan-secrets](scan-secrets/) | credentials in staged changes | 5/5 |
| [verify-dependency-exists](verify-dependency-exists/) | dependencies absent from your allowlist | 5/5 |

## Enforced before the tool runs

Guard scripts wired into PreToolUse. They reach `enforced` only after
`chock sync`; before that they are compiled fragments that enforce nothing,
and coverage says so.

| Policy | Refuses | Evals |
| :--- | :--- | ---: |
| [block-destructive-commands](block-destructive-commands/) | `rm -rf /`, force push, hard reset, `terraform destroy` | 6/6 |
| [block-no-verify](block-no-verify/) | `--no-verify`, which bypasses every gate above | 3/3 |

## Advisory

Rule text compiled into the agent's context. Nothing executes. These have **no executable
eval cases** — there is no mechanism to replay, so their suites describe intended behaviour
rather than a verified control, and `chock check --only evals` reports them as `skipped`, never as
passing.

| Policy | Addresses |
| :--- | :--- |
| [agent-discipline](agent-discipline/) | editing unread files, unverified "done", tests weakened to pass |
| [code-safety](code-safety/) | secrets, `eval`/`exec`, unsanitised SQL, invented dependencies |
| [context-hygiene](context-hygiene/) | context bloat, stale observations, lost-in-the-middle |
| [git-safety](git-safety/) | force push, hard reset, branch deletion, direct `main` commits |
| [injection-defense](injection-defense/) | instructions found in tool output treated as commands |
| [memory-discipline](memory-discipline/) | memory filling with what the repo already records |
| [token-efficiency](token-efficiency/) | context spent on output nobody reads |

### Why the advisory ones repeat the enforced ones

`git-safety` restates parts of `block-destructive-commands`, `block-no-verify` and
`protect-main-branch`; `code-safety` restates parts of `scan-secrets` and
`verify-dependency-exists`.

That is deliberate. Adoption is à la carte, so each policy has to stand alone —
de-duplicating them would mean an adopter who installs only `git-safety` silently loses
guidance its text promises. The cost is a few repeated lines when several are installed
together; the alternative is a policy that is only complete if you happened to install its
neighbours.

## How these pages stay true

The facts in each page — type, mechanism, enforcement ceiling, gate parameters, eval counts,
compiled surfaces — are derived from `base/<id>/` by `tools/gen_policy_docs.py`, and CI runs
it with `--check`. A page that contradicts its policy fails the build.

Only judgement is hand-written, in [`policy-prose.yaml`](policy-prose.yaml): why the policy
exists and what is safe to change. Editing a generated page directly will be overwritten —
edit the prose file, or the policy.

```bash
python tools/gen_policy_docs.py           # regenerate
python tools/gen_policy_docs.py --check   # what CI runs
```

This split is the point. Twelve hand-written policy docs drift the first time a policy
changes, and a doc claiming `enforced` about advisory text is the exact overclaim this
project exists to prevent — published where adopters read first.
