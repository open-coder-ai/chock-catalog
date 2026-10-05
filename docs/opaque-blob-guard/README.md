# Flag Opaque Blobs

`opaque-blob-guard` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | warns — warns on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | warn-only `script` gate |
| **Reaches** | `advisory` — the gate runs and prints its findings; it never refuses |
| **Compiles to** | `git-hook`, `ci-gate`, `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 17 total, 17 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe rollout; never refuses yet) when a change adds or edits, in tests/, fixtures/, testdata/, spec/, m4/, vendor/, gradle/wrapper/: a file whose first bytes are an archive, executable, wasm or database signature (any extension), a random-looking non-media file over 100 KB, or a symlink out of the repo; m4/configure/Makefile text that decodes and evaluates; a gradle wrapper jar changed with no new distributionSha256Sum. Misses text-encoded or prefixed payloads, other folders.

## What it solves

A payload hidden in a test file is how the xz backdoor reached the build (a corrupt-looking xz test file, extracted by an m4 macro at configure time). Reviewers read source, not binaries, and tests/, fixtures/, testdata/ and vendor/ are where unreadable files are expected. This gate reads each changed file in those paths by its first bytes, whatever its name, and also flags a random-looking file over 100 KB, a symlink that leaves the repository, build text (m4, configure, Makefile.am) that decodes and evaluates, and a changed gradle wrapper jar with no new distributionSha256Sum. It warns while its false-positive rate is measured.

## How it works

A `script` gate runs on `commit` and `tool_use` and only warns: its action is `warn`, so it prints its findings and never refuses. It does not enforce anything, so the policy counts as advisory.

On a finding it prints:

> A change adds or edits a file a reviewer cannot read in a test, fixture, vendor or gradle wrapper path: an archive, executable or wasm module (by its first bytes, whatever its name), a random-looking file over 100 KB, a symlink out of the repository, build text that decodes and evaluates data, or a gradle wrapper jar changed with no new distributionSha256Sum. A hidden payload in a test file is how the xz backdoor reached build scripts. Generate the data in the test setup or fetch it from a pinned, checksummed source; if the file must be committed, state why and have a person list '<sha256> <path>' in .chock/blob-allowlist.txt. An agent asks a person: an entry written in the same agent change does not count at tool use or in an agent's commit (keep the allowlist under code-owner review). This policy only warns while it is measured (rollout observe).

The rule text ships alongside, in the agent's ambient context:

```text
binary_or_archive_in(tests|fixtures|testdata|spec|m4|vendor|gradle/wrapper): avoid; if_required: state(purpose), list(sha256+path in .chock/blob-allowlist.txt), person_commits
prefer: generate_in_test_setup | pinned_checksummed_download; never decode_and_eval(test_file)
```

## Which primitive it becomes

A **warn-only gate**. `recompile` writes it under `.chock/compiled/opaque-blob-guard/` for each surface its `on` names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but its exit never refuses a commit or a write.

## Installing it

```bash
chock add opaque-blob-guard
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/opaque-blob-guard  <your-repo>/.agents/policies/opaque-blob-guard
cd <your-repo> && chock sync --repo .
```

## Customising it

The signatures, scoped folders, entropy limits, build-text patterns and the known gradle wrapper hashes (empty by default, a list of lowercase sha256) live in `implementations/data/*.json`. A file that must stay is listed as `<sha256>  <path>` in `.chock/blob-allowlist.txt`: both must match, one malformed line ignores the whole list, and at tool use and in an agent's commit only entries already in HEAD count, but a person's commit and CI read the staged list, so keep that file under code-owner review. Known limits: shell sinks written as a variable (`$SHELL`), a newline after the pipe, assign-then-eval and redirect-then-run are not recognised; a repo_root whose own name is a scoped folder loses that scope; offset-0 signatures only (a prefixed archive, text-encoded data of any size, and known media headers followed by random bytes are missed); only the first 4 MiB is entropy-sampled; folders outside the scoped list are not judged, and folder names match by exact case and spelling (`Vendor`, `VENDOR`, `Spec`, `third-party`, `test-data` are not scoped); a payload split across many small files, a Python bytecode file and a Git LFS pointer are not recognised; a commit of several thousand in-scope files can exceed the runner's 30 s script budget and is then left undecided; a Makefile that runs a script under tests/ (`sh tests/run.sh`) or a `| sh` within 2000 characters of an unrelated decompressor line is asked about; the runner quotes odd file names (a double quote or backslash) so such files may never reach the gate.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals opaque-blob-guard
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/opaque-blob-guard/`](../../base/opaque-blob-guard/) · [all policies](../README.md)
