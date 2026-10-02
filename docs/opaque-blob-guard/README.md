# Flag Opaque Blobs

`opaque-blob-guard` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 17 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe rollout; never refuses yet) when a change adds or edits, in tests/, fixtures/, testdata/, spec/, m4/, vendor/, gradle/wrapper/: a file whose first bytes are an archive, executable, wasm or database signature (any extension), a random-looking non-media file over 100 KB, or a symlink out of the repo; m4/configure/Makefile text that decodes and evaluates; a gradle wrapper jar changed with no new distributionSha256Sum. Misses text-encoded or prefixed payloads, other folders.

## What it solves

A payload hidden in a test file is how the xz backdoor reached the build (a corrupt-looking xz test file, extracted by an m4 macro at configure time). Reviewers read source, not binaries, and tests/, fixtures/, testdata/ and vendor/ are where unreadable files are expected. This gate reads each changed file in those paths by its first bytes, whatever its name, and also flags a random-looking file over 100 KB, a symlink that leaves the repository, build text (m4, configure, Makefile.am) that decodes and evaluates, and a changed gradle wrapper jar with no new distributionSha256Sum. It warns while its false-positive rate is measured.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
binary_or_archive_in(tests|fixtures|testdata|spec|m4|vendor|gradle/wrapper): avoid; if_required: state(purpose), list(sha256+path in .chock/blob-allowlist.txt), person_commits
prefer: generate_in_test_setup | pinned_checksummed_download; never decode_and_eval(test_file)
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/opaque-blob-guard/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

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
