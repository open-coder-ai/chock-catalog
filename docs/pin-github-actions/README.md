# Pin GitHub Actions

`pin-github-actions` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 9 total, 9 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Pre-commit gate for the mechanizable slice of CI supply-chain hardening: a workflow that references a third-party GitHub Action by a movable ref -- a branch or a version tag -- instead of a full 40-character commit SHA. A tag like v4 or a branch like main can be re-pointed at new code after review, so the action that runs tomorrow need not be the one that was audited today; a compromised or rug-pulled release rides in on exactly that mutability. The gate blocks an added line that references an action by a non-SHA ref (owner/repo at a tag/branch); a full 40-char SHA pin passes, local actions (no ref) pass, and 'pragma: allowlist unpinned-action' on the same line is a visible, deliberate exception. This is the OpenSSF Scorecard Pinned-Dependencies control for the slice a diff can show; signature and provenance verification stay out of scope.

## What it solves

The one line of a workflow that trusts code it never froze. `owner/action` at a tag or branch resolves to whatever that ref points at when the job runs -- and the owner of the action, or anyone who compromises them, can move the tag to new code after the pull request that added it was reviewed and merged. The CI runner has repository secrets; the audited line and the executed line are simply not the same thing until the ref is a commit SHA.

## How it works

A declarative `content_regex` gate, evaluated on `commit`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Unpinned GitHub Action detected: a workflow references an action by a tag or branch (owner/repo at a movable ref) rather than a full 40-character commit SHA. Pin it to the SHA -- keep the version in a trailing comment for readability -- so a re-tagged or compromised release cannot change what runs. For a deliberate exception, add 'pragma: allowlist unpinned-action' on the same line.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/pin-github-actions/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add pin-github-actions
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/pin-github-actions  <your-repo>/.agents/policies/pin-github-actions
cd <your-repo> && chock sync --repo .
```

## Customising it

The gate blocks any action referenced by a non-SHA ref and passes a full 40-char SHA or a local (ref-less) action; the pattern lives in the manifest's `content_pattern`. It is strict on purpose -- even a specific version tag is re-pointable -- so a repo that has decided a trusted tag is acceptable marks the line with `pragma: allowlist unpinned-action`, which keeps the exception visible in the diff. Pair it with Dependabot to bump the pinned SHAs; signature and provenance verification are a separate, heavier control this does not attempt.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals pin-github-actions
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/pin-github-actions/`](../../base/pin-github-actions/) · [all policies](../README.md)
