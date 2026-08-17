# Block Unpinned Agent Components

`block-unpinned-agent-components` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 6 total, 6 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Pre-commit gate for the mechanizable slice of ASI04: agent components pulled at an unpinned version. Blocks npx/uvx/bunx launches at @latest — the standard MCP server idiom — quoted "@latest" arguments in agent config, and :latest container images. Language-manifest dependencies are verify-dependency-exists; signature and provenance stay with the advisory owasp-asi04 policy. Escape: 'pragma: allowlist unpinned' on the same line.

## What it solves

The MCP server added as `npx -y something@latest`, which re-resolves on every start. What was reviewed on Tuesday is not what runs on Thursday, and nothing in the repo records the switch. The ASI04 supply-chain policy can advise about provenance all it likes; the floating version is the part a diff literally states.

## How it works

A declarative `content_regex` gate, evaluated on `commit`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Unpinned agent component detected. Pin the version (name@1.2.3, image:tag) so what runs tomorrow is what was reviewed today, or add 'pragma: allowlist unpinned' on the same line for a deliberate exception.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/block-unpinned-agent-components/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add block-unpinned-agent-components
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/block-unpinned-agent-components  <your-repo>/.agents/policies/block-unpinned-agent-components
cd <your-repo> && chock sync --repo .
```

## Customising it

The launcher list (`npx|uvx|bunx`) is the part to extend when your stack grows a new runner. Resist adding bare-launcher matching (no version suffix at all) -- it needs a parser, not a regex, and would flag every `npx` line. Dev-only compose files keep `:latest` honestly via the pragma, in the diff where review can see it.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-unpinned-agent-components
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/block-unpinned-agent-components/`](../../agentic-security/block-unpinned-agent-components/) · [all policies](../README.md)
