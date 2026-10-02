# Flag Fetch-Exec in Files

`block-fetch-exec-in-files` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 20 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe rollout) when a line added to a script, Dockerfile, Makefile, CI workflow or package.json wires a download into a code runner: curl/wget/aria2c/lynx/iwr/irm piped into a shell, python/perl/ruby/node/php/lua on stdin, pwsh or iex; bash -c, eval, source or a here-string of a $(...) or <(...) download; Dockerfile ADD of a URL without --checksum. One line at a time: continuation lines and variables are missed. Never refuses. Friction only.

## What it solves

The install line that outlives the conversation. A command guard sees an agent run a download straight into a shell once; written into a Dockerfile, Makefile, CI step or npm postinstall, the same wiring runs on every build, with that environment's credentials, and whoever controls the URL decides what it does each time.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
flag(fetch_exec_in_file): added line wires a downloader (curl, wget, iwr, irm) into a shell or interpreter by pipe, $(..), <(..) or here-string; Dockerfile ADD <url> without --checksum
prefer: download to a file, verify (sha256sum -c, gpg --verify, ADD --checksum=sha256:...), then run; waiver: same-line pragma, person only
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/block-fetch-exec-in-files/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add block-fetch-exec-in-files
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/block-fetch-exec-in-files  <your-repo>/.agents/policies/block-fetch-exec-in-files
cd <your-repo> && chock sync --repo .
```

## Customising it

It only warns while its false-positive rate is measured (rollout observe); a later version is meant to block. It reads one added line at a time inside applies_to.paths, so a pipe split across a continuation line or a URL held in a variable is not seen. Prefer download, verify (sha256sum -c, gpg --verify, Dockerfile ADD --checksum=sha256:...), then run. A reviewed exception is marked with `pragma: allowlist fetch-exec` on the same line; an agent asks a person to add it.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals block-fetch-exec-in-files
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/block-fetch-exec-in-files/`](../../base/block-fetch-exec-in-files/) · [all policies](../README.md)
