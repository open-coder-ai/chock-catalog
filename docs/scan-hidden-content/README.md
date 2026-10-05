# Scan Hidden Content

`scan-hidden-content` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | warns — warns on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | warn-only `script` gate |
| **Reaches** | `advisory` — the gate runs and prints its findings; it never refuses |
| **Compiles to** | `git-hook`, `ci-gate`, `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 45 total, 44 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe) when a change adds text a reader cannot see, or a URL that carries data out, to Markdown, HTML, SVG, XML, Word, agent instruction files, docs and templates: instruction-like or long comments, CSS-hidden, white or 1pt text, hidden Word runs, URLs with secret words, long queries, placeholders or encoded parts, remote embeds, camo runs, HTML data URIs. Runs: commit, agent write, turn's end. Waiver: a person's marker comment line above. Friction, not a boundary.

## What it solves

A page can show a reviewer one thing and an agent another. A comment the renderer never shows, a span styled out of sight, white or zero-size text, or a Word run marked hidden can carry instructions an agent reads and a person never sees; an image URL whose query holds a token or a data-shaped part sends data out the moment the page is rendered. This gate reads what a change adds to Markdown, HTML, SVG, XML and Word files, agent instruction files, docs and issue or pull-request templates, and flags each such comment, hidden element and URL. It warns while its false-positive rate is measured; a later release asks, and blocks a URL whose query names a secret.

## How it works

A `script` gate runs on `commit` and `tool_use` and only warns: its action is `warn`, so it prints its findings and never refuses. It does not enforce anything, so the policy counts as advisory.

On a finding it prints:

> This change adds text a reader cannot see (a comment or hidden element that reads as an instruction, white or zero-size text) or a URL that can carry data out (a secret word or data-shaped part in its query or path, a remote embed, a dictionary of image URLs). Remove the hidden text or make it visible, and link only to fixed URLs that carry nothing from the repository or the session. A person may keep a reviewed line with a comment line just above it that holds only 'chock: allow scan-hidden-content', committed from their own shell; in the agent only a waiver already committed in HEAD counts, so an agent asks the person instead.

## Which primitive it becomes

A **warn-only gate**. `recompile` writes it under `.chock/compiled/scan-hidden-content/` for each surface its `on` names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but its exit never refuses a commit or a write.

## Installing it

```bash
chock add scan-hidden-content
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/scan-hidden-content  <your-repo>/.agents/policies/scan-hidden-content
cd <your-repo> && chock sync --repo .
```

## Customising it

A reviewed line is kept by a person with `chock: allow scan-hidden-content` on it, or on a comment line just above, committed from their own shell; in the agent a waiver counts only for a line already in HEAD. A Word document cannot carry the waiver. The host allowlist and the vocabulary live in the policy's data table; widening them is a change to the policy.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals scan-hidden-content
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/scan-hidden-content/`](../../base/scan-hidden-content/) · [all policies](../README.md)
