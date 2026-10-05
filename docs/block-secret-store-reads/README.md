# Block Secret Store Reads

`block-secret-store-reads` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — refuses a matched shell command before it runs |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | guard script `block-secret-store-reads.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 89 total, 89 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against an agent reading credentials from the shell: cat, grep, sed, cp, tar, base64, source or < on ~/.ssh (not .pub), ~/.aws, ~/.npmrc, ~/.netrc, ~/.kube, ~/.gnupg, agent CLI dirs, browser login DBs, wallets, .env (not .env.example), *.tfstate; interpreter one-liners naming them; gh auth token, aws sts get-session-token, git credential fill. Asks on env/printenv dumps. Misses: scripts, unresolved variables, xargs lists, $(...) results.

## What it solves

A prompt-injected or careless agent can read a developer's credentials with one ordinary command: `cat ~/.npmrc`,
`base64 ~/.aws/credentials`, `tar czf x.tgz ~/.ssh`, `gh auth token`. Once the value is in the transcript it
can be sent anywhere, and the supply-chain worms of 2025 (s1ngularity, Shai-Hulud) did exactly this with the
victim's own agent CLI. This guard refuses the read before it runs and tells the agent to ask the person for
the one value it needs. Template files, listings and public keys stay readable.

## How it works

A guard script, `implementations/block-secret-store-reads.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
never(read|print): credential_stores(~/.ssh(not_*.pub)|~/.aws|~/.npmrc|~/.netrc|~/.kube|~/.gnupg|agent_cli_dirs|browser_dbs|wallets|.env(not_.env.example)|*.tfstate)|tokens(gh_auth_token|aws_sts|git_credential_fill), via(cat|grep|sed|cp|tar|base64|source|<|interpreter)
ask: env|printenv|set|export_-p  # dumps every secret; if(value_needed): ask_person_for_that_value
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-secret-store-reads/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-secret-store-reads
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-secret-store-reads  <your-repo>/.agents/policies/block-secret-store-reads
cd <your-repo> && chock sync --repo .
```

## Customising it

The stores, readers and token printers are one data file, `implementations/data/secret_stores.json`
(365-day freshness, checked in CI); add a path or a reader there and an eval case beside it. A store that is a
directory needs no per-file rows. `relative` says whether a bare relative name may match (`always`, `code` for
interpreter text only, `never`). Nothing waives a refusal in-band: the person runs the command themselves.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-secret-store-reads
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-secret-store-reads/`](../../base/block-secret-store-reads/) · [all policies](../README.md)
