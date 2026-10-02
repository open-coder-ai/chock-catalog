# Scan Hidden Content

`scan-hidden-content` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: advise`) |
| **Mechanism** | guard script `scan-hidden-content-gate.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 39 total, 38 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe) when a change adds text a reader cannot see, or a URL that carries data out, to Markdown, HTML, SVG, XML, Word, agent instruction files, docs and templates: imperative or long HTML comments, CSS-hidden, white or 1pt text, URLs with secret words, long queries, placeholders or encoded parts, remote embeds, camo runs, HTML data URIs. Runs: commit, agent write, turn's end. A person's waiver: 'chock: allow scan-hidden-content'. Friction, not a boundary.

## What it solves

A page can show a reviewer one thing and an agent another. A comment the renderer never shows, a span styled out of sight, white or zero-size text, or a Word run marked hidden can carry instructions an agent reads and a person never sees; an image URL whose query holds a token or a data-shaped part sends data out the moment the page is rendered. This gate reads what a change adds to Markdown, HTML, SVG, XML and Word files, agent instruction files, docs and issue or pull-request templates, and flags each such comment, hidden element and URL. It warns while its false-positive rate is measured; a later release asks, and blocks a URL whose query names a secret.

## How it works

A guard script, `implementations/scan-hidden-content-gate.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text

```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/scan-hidden-content/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add scan-hidden-content
chock sync .
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
