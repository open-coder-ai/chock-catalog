# Block Curl-Pipe-Shell

`block-curl-pipe-sh` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-curl-pipe-sh.sh` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 27 total, 27 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against piping a network download straight into a shell or script interpreter: curl|wget|iwr ... | sh/bash/zsh/python/perl/ruby/node (bare or path-qualified, including subshell groups and sudo/exec/command/env wrappers), bash -c "$(curl ...)", bash <(curl ...), and the PowerShell iwr ... | iex form. Downloading to a file, or piping a fetch into a non-interpreter tool (jq, tar, grep), stays allowed. Known bypass classes include aliases, variable indirection, base64/obfuscated payloads, env-var-prefixed interpreters, and non-standard fetch clients. This is friction, not a security boundary.

## What it solves

The install instruction that runs code nobody read: `curl https://get.example.com | sh`. The bytes the server returns are executed the instant they arrive -- a compromised host, a redirected URL, or a payload that varies by user-agent all land as root-capable shell with no diff, no pin, and no chance to look first. It is the plainest supply-chain vector an agent will reach for, because every project's README suggests it.

## How it works

A guard script, `implementations/block-curl-pipe-sh.sh`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
block(remote_exec): fetch(curl|wget|iwr|irm) piped/substituted into interpreter(sh|bash|python|perl|node|iex)
allow: download_to_file, fetch|non_interpreter(jq|tar); prefer: curl -o file; read; run
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-curl-pipe-sh/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-curl-pipe-sh
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-curl-pipe-sh  <your-repo>/.agents/policies/block-curl-pipe-sh
cd <your-repo> && chock sync --repo .
```

## Customising it

The guard blocks only a fetch wired DIRECTLY into a shell or script interpreter (a pipe, `bash -c "$(...)"`, or `bash <(...)`) -- `sh`/`bash`/`zsh` and `python`/`perl`/`ruby`/`node` alike, since piping a download into any of them runs the fetched code. Download-to-file and pipes into a non-interpreter tool (`jq`, `tar`, `grep`) stay allowed, because the safe form it points you toward -- fetch, read, then run -- must not itself be blocked. It matches the raw command text with regexes (it does not tokenize), so add your own fetch clients or interpreters there; read the manifest description first for the bypass classes (aliases, variable indirection, obfuscation) it cannot see.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-curl-pipe-sh
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-curl-pipe-sh/`](../../base/block-curl-pipe-sh/) · [all policies](../README.md)
