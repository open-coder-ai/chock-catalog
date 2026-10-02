# Block Curl-Pipe-Shell

`block-curl-pipe-sh` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-curl-pipe-sh.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 60 total, 60 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard on parsed commands: refuses a download wired into a shell or interpreter (sh..fish, python, perl, ruby, node, php, lua, pwsh, deno, bun, busybox, su, $SHELL, source, eval, iex) by pipe, substitution, here-string or process substitution, also inside bash -c/ssh/docker exec bodies, or downloaded and run in one command with no checksum or signature step. nc/socat/one-liner reads ask. Misses: aliases, functions, variables set outside the command, encoded text. Friction only.

## What it solves

The install instruction that runs code nobody read: `curl https://get.example.com | sh`. The bytes the server returns are executed the instant they arrive -- a compromised host, a redirected URL, or a payload that varies by user-agent all land as root-capable shell with no diff, no pin, and no chance to look first. It is the plainest supply-chain vector an agent will reach for, because every project's README suggests it.

## How it works

A guard script, `implementations/block-curl-pipe-sh.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
block(remote_exec): fetch(curl|wget|iwr|irm) piped|substituted|here-string|run-after-download into interpreter(sh|bash|python|php|pwsh|source|eval|iex), quoted bodies too; ask: nc|socat|net one-liner
allow: download_to_file, fetch|non_interpreter(jq|tar|gpg), download+verify(sha256sum -c|gpg --verify)+run; prefer: curl -o file; read; verify; run
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
