# Flag Fetch-Exec in Files

`block-fetch-exec-in-files` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | warns — warns on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | warn-only `content_regex` gate |
| **Reaches** | `advisory` — the gate runs and prints its findings; it never refuses |
| **Compiles to** | `git-hook`, `ci-gate`, `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 25 total, 25 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe rollout) when a line added to a script, Dockerfile, Makefile, CI workflow or package.json wires a download into a code runner: curl/wget/aria2c/lynx/iwr/irm piped into a shell, python/perl/ruby/node/php/lua on stdin, pwsh or iex; bash -c, eval, source or a here-string of a $(...) or <(...) download; Dockerfile ADD of a URL without --checksum. One line at a time: continuation lines, variables, unicode-escaped JSON, split or quoted command names, a download saved to a file and run on a later step, and interpreters or fetchers outside the lists are missed. Never refuses. Friction only.

## What it solves

The install line that outlives the conversation. A command guard sees an agent run a download straight into a shell once; written into a Dockerfile, Makefile, CI step or npm postinstall, the same wiring runs on every build, with that environment's credentials, and whoever controls the URL decides what it does each time.

## How it works

A `content_regex` gate runs on `commit` and `tool_use` and only warns: its action is `warn`, so it prints its findings and never refuses. It does not enforce anything, so the policy counts as advisory.

On a finding it prints:

> A line added to a build, CI or install file wires a network download straight into a shell or interpreter (or ADDs a URL without --checksum), so whoever controls that URL controls what runs. Download to a file, verify it (sha256sum -c against a pinned checksum, gpg --verify, or ADD --checksum=sha256:...), then run it as a separate step. This policy only warns while it is measured. Waiver: 'pragma: allowlist fetch-exec' on the same line. A person's commit honours it; in the agent only a line already in HEAD counts. An agent asks a person; it never writes the pragma.

The rule text ships alongside, in the agent's ambient context:

```text
flag(fetch_exec_in_file): added line wires a downloader (curl, wget, iwr, irm) into a shell or interpreter by pipe, $(..), <(..) or here-string; Dockerfile ADD <url> without --checksum
prefer: download to a file, verify (sha256sum -c, gpg --verify, ADD --checksum=sha256:...), then run; waiver: same-line pragma, person only
```

## Which primitive it becomes

A **warn-only gate**. `recompile` writes it under `.chock/compiled/block-fetch-exec-in-files/` for each surface its `on` names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but its exit never refuses a commit or a write.

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
