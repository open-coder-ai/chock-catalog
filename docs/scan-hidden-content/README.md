# Scan Hidden Content

`scan-hidden-content` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 45 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe) when a change adds text a reader cannot see, or a URL that carries data out, to Markdown, HTML, SVG, XML, Word, agent instruction files, docs and templates: instruction-like or long comments, CSS-hidden, white or 1pt text, hidden Word runs, URLs with secret words, long queries, placeholders or encoded parts, remote embeds, camo runs, HTML data URIs. Runs: commit, agent write, turn's end. Waiver: a person's marker comment line above. Friction, not a boundary.

## What it solves

A page can show a reviewer one thing and an agent another. A comment the renderer never shows, a span styled out of sight, white or zero-size text, or a Word run marked hidden can carry instructions an agent reads and a person never sees; an image URL whose query holds a token or a data-shaped part sends data out the moment the page is rendered. This gate reads what a change adds to Markdown, HTML, SVG, XML and Word files, agent instruction files, docs and issue or pull-request templates, and flags each such comment, hidden element and URL. It warns while its false-positive rate is measured; a later release asks, and blocks a URL whose query names a secret.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text

```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/scan-hidden-content/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

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
