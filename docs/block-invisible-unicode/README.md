# Block Invisible Unicode

`block-invisible-unicode` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 8 total, 8 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

The mechanizable slice of prompt-injection defense, enforced at two points: at commit (the git hook, over staged changes) and at agent tool-use (over a tool call's arguments, as the agent writes) -- invisible and direction-override Unicode. Bidi controls make code read differently than it parses (Trojan Source, CVE-2021-42574); Unicode tag-block characters smuggle instructions that are invisible to a human reviewer but fully legible to the agent reading the file. Zero-width joiners and bidi marks (ZWJ/ZWNJ/LRM/RLM) are deliberately NOT matched -- they are legitimate in emoji sequences and in Persian, Arabic and Indic text -- so ordinary internationalised content passes; only the override/embed/isolate controls and the tag block, which have no honest use in a source tree, are blocked. Escape: 'pragma: allowlist invisible-unicode' on the same line.

## What it solves

The one slice of prompt injection a diff can literally show. Bidi override characters make code read differently to a human than it parses (Trojan Source, CVE-2021-42574), and Unicode tag-block characters carry instructions a reviewer cannot see but the agent reading the file will happily obey. Both arrive through the most ordinary channel there is: a commit.

## How it works

A declarative `content_regex` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Invisible or direction-override Unicode detected in this change. These characters change how code reads to a human or hide instructions an agent will still obey. Remove them. At commit, 'pragma: allowlist invisible-unicode' on the same line marks a documented exception (e.g. a test fixture); the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.

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
