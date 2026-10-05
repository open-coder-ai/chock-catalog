# Block Unpinned Agent Components

`block-unpinned-agent-components` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 54 total, 54 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Gate for the line-visible slice of ASI04: agent components fetched at a floating version. Blocks dist-tags (latest, next, canary, beta, rc, nightly) on npx/uvx/bunx, dlx, add/install and pipx run; FROM at latest or an untagged registry path; floating docker run/pull and docker:// refs; pip --pre; go install at latest; unversioned cargo installs; git+ installs and requirements, and github: dependencies, with no commit SHA. Per line: friction, not a boundary (limits in references).

## What it solves

The MCP server added as `npx -y something@latest`, which re-resolves on every start. What was reviewed on Tuesday is not what runs on Thursday, and nothing in the repo records the switch. The ASI04 supply-chain policy can advise about provenance all it likes; the floating version is the part a diff literally states.

## How it works

A declarative `content_regex` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Unpinned agent component detected. Pin an exact version or digest (name@1.2.3, image:1.27.1 or image@sha256:..., a 40-hex commit for git+ and github: refs, cargo install name@1.2.3, no pip --pre) so what runs tomorrow is what was reviewed today, or add 'pragma: allowlist unpinned' on the same line for a deliberate exception (a person's; in the agent it counts only when that exact line is already committed in HEAD, so an agent asks a person).

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
