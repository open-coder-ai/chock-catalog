# context-report measurements of chock's plugin bundles

Measured facts about the plugin bundles this catalog's `base/` policies build into, one
[context-report](https://github.com/open-coder-ai/context-report) statement per bundle and
condition, kept next to the artifacts they describe: the report travels with the plugin, not
with the format.

## What was measured

- **Subjects**: the 22 `base/` policies, each built with `chock plugin build --format all`
  (chock 0.8.0) into a bundle for Claude Code, Codex CLI, GitHub Copilot and Cursor -- 88 bundles.
  Four policies carry a pre-tool hook (`block-destructive-commands`, `block-no-verify`,
  `protect-agent-config`, `protect-commit-privacy`), so 16 bundles have something to execute.
- **Conditions**: every hook bundle was measured twice. `resolved` sets the plugin-root variable
  the client would set (`CLAUDE_PLUGIN_ROOT`, `PLUGIN_ROOT`, `CURSOR_PLUGIN_ROOT`); `unresolved`
  blanks it to empty (the shell expands that the same as unset).
- **Producer**: context-report at `41088e5` (`main`), `n = 20` latency samples, on a four-CPU
  Linux machine on 2026-09-06. Every statement validates against the v0.1 schema and binds to its
  bundle tree's sha256.

`SUMMARY.md` is the per-format roll-up; `chock/<format>/<policy>[.condition].json` are the
statements.

## What the rows say

**Reachability is a property of the client's variable, not the script.** With the variable set,
all 16 hooks run from all four working directories tested (bundle root, a nested directory, the
parent, a directory outside the tree). Without it, none run for Claude Code, Codex CLI or Cursor:
the interpreter cannot open `/scripts/<agent>.py`. The Copilot bundle reads as reachable in both
conditions because its command is written to `exit 0` when the variable is unset; the row records
that exit, and the benign control case under `fault.malformedOutput` shows the guard did not run.

**Every hook exits 0 with no deny on malformed input.** Fed unparseable JSON, empty stdin or a null
tool input, all 16 hooks exit 0 and write nothing to stdout, so the tool call proceeds. This is the
adapter's documented choice, not an accident: the agentseam runtime template chock generates from
comments the branch "malformed input is not the agent's fault to pay for: allow, stay silent." The
row states the fact; whether to fail closed there is a chock decision.

**Latency is a distribution with a floor.** With a realistic pre-tool payload, the median hook
bundle's p50 is 38.1 to 42.8 ms depending on the target adapter, and the median p95 per target is
within 5 ms of its p50; individual bundles range from 39.7 to 48.4 ms at p95. The unresolved
condition's `cost.latency_ms` row is now `Error` with no kept measurement -- the interpreter floor
is still ~12 ms, run directly. These rows are `environmentSensitive`; read the shape, not the number.

**Context weight.** Under `approx-regex-v1`, the median bundle adds an estimated 222 tokens; the 72
bundles without a hook range from 173 to 611, the 16 with a hook from 298 to 725 (Copilot's hooks
file is now counted too).

| Target | Bundles | With hook | Reachable, resolved | Reachable, unresolved | Exit 0 and no deny on malformed stdin | Latency p50 / p95 ms, median over hook bundles |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Claude Code | 22 | 4 | 4 of 4 | 0 of 4 | 4 of 4 | 42.8 / 46.0 |
| Codex CLI | 22 | 4 | 4 of 4 | 0 of 4 | 4 of 4 | 39.8 / 44.2 |
| GitHub Copilot | 22 | 4 | 4 of 4 | 4 of 4 | 4 of 4 | 38.1 / 41.2 |
| Cursor | 22 | 4 | 4 of 4 | 0 of 4 | 4 of 4 | 38.3 / 40.8 |

**What changed since the first pass.** Context-token names are now subject-relative, and hooks are
discovered from the plugin itself, not guessed by `dogfood.py` -- meant to leave the numbers
alone, and did, except Copilot's context weight above. `reachability` and `fault.malformedOutput`
are unchanged.

## Reproduce

```bash
pip install "context-report @ git+https://github.com/open-coder-ai/context-report@main"
for p in base/*/; do chock plugin build --repo . --policies-dir base --format all --out-dir /tmp/chock-bundles; done
python3 measurements/context-report/inventory.py --bundles /tmp/chock-bundles --out measurements/context-report/inventory.json
python3 measurements/context-report/dogfood.py --bundles /tmp/chock-bundles \
  --targets measurements/context-report/inventory.json --out measurements/context-report/chock --n 20
```

Re-derivable rows (reachability, malformed-output, context tokens) come back identical for
identical bundle digests; latency comes back comparable, not identical. A digest mismatch means
the bundle was rebuilt and the statement no longer matches it.
