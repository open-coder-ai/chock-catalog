# Block Unsafe Code Execution

`block-unsafe-code-execution` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `hook` (`enforcement: block`) |
| **Mechanism** | content_regex gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 7 total, 7 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Pre-commit gate for the mechanizable slice of ASI05: bare eval/exec, shell-mode subprocess calls, os.system, pickle/marshal loads, yaml.load without SafeLoader, execSync, new Function. Best-effort line scan; sandbox design, egress, and inherited credentials stay with the advisory owasp-asi05 policy. Escape hatch for vetted uses: 'pragma: allowlist exec' on the same line.

## What it solves

The one-line distance between "agent output" and "arbitrary code": a bare `eval(`, a `shell=True`, a `pickle.loads` on bytes the agent fetched. Each is a single token in a diff, which makes them the rare ASI05 slice a commit-time gate can actually see.

## How it works

A declarative `content_regex` gate, evaluated on `commit`, action `block`.

Parameters, from `manifest.yaml`:

- `allowlist_pragma`
- `content_pattern`
- `scan`

On a match it prints:

> Dynamic execution primitive detected. Replace it with a parameterized API (subprocess argument vector, safe_load, a real parser), or add 'pragma: allowlist exec' on the same line for a reviewed, deliberate use.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/block-unsafe-code-execution/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add block-unsafe-code-execution
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r agentic-security/block-unsafe-code-execution  <your-repo>/.agents/policies/block-unsafe-code-execution
cd <your-repo> && chock sync --repo .
```

## Customising it

Add your stack's own sinks -- template engines with code execution, `Function` constructors in other guises. The lookbehind excluding dotted calls (`model.eval()`, `pattern.exec()`) is what keeps this gate satisfiable; if you find yourself deleting it to catch more, you are about to teach every adopter to disable the policy instead.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-unsafe-code-execution
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`agentic-security/block-unsafe-code-execution/`](../../agentic-security/block-unsafe-code-execution/) · [all policies](../README.md)
