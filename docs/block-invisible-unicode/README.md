# Block Invisible Unicode

`block-invisible-unicode` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 61 total, 61 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks hidden Unicode in added lines: bidi, tag and plane-14 chars, word joiner, chained invisibles, zero-width/joiners/fillers by ASCII, mid-line BOM, LRM/RLM outside RTL text, selectors after ASCII, private-use runs of 16+. Allows emoji, RTL/Indic/Thai/CJK text, line-start BOM. Not caught: homoglyphs, a joiner between non-ASCII, binary files and text after U+2028 at commit. Runs: commit, agent write, turn's end. Waiver: 'pragma: allowlist invisible-unicode' same line; agent: HEAD only.

## What it solves

The one slice of prompt injection a diff can literally show. Bidi override characters make code read differently to a human than it parses (Trojan Source, CVE-2021-42574), and Unicode tag-block characters carry instructions a reviewer cannot see but the agent reading the file will happily obey. Both arrive through the most ordinary channel there is: a commit.

## How it works

A declarative `content_regex` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Hidden Unicode detected in this change: a bidi control, a tag character, a word joiner, two invisible characters in a row, a zero-width character, joiner or filler beside ASCII, a BOM after the start of a line, a direction mark outside right-to-left text, a variation selector after ASCII, or a long private-use run. It changes how code reads to a human or hides instructions an agent will still obey. Remove it; where the character is meant, write it as an escape sequence instead. Waiver: 'pragma: allowlist invisible-unicode' on the same line. A person's commit honours it; in the agent (write, the turn's end, an agent's commit) only a line already in HEAD counts, and the MCP gateway never does. An agent asks a person; it never writes the pragma.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/block-invisible-unicode/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add block-invisible-unicode
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-invisible-unicode  <your-repo>/.agents/policies/block-invisible-unicode
cd <your-repo> && chock sync --repo .
```

## Customising it

The deliberate exclusions are the tuning surface. ZWJ/ZWNJ and the LRM/RLM marks are not matched because emoji sequences and Persian, Arabic and Indic text use them honestly; if your repo contains no internationalised content and you want the stricter net, add them to the character class. Keep the pattern as escapes, never literal characters -- the gate must not carry the bytes it blocks.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-invisible-unicode
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-invisible-unicode/`](../../base/block-invisible-unicode/) · [all policies](../README.md)
