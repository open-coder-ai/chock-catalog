# Flag Opaque Blobs

`opaque-blob-guard` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | guard script `opaque-blob-guard-gate.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 17 total, 17 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Warns (observe rollout; never refuses yet) when a change adds or edits, in tests/, test/, fixtures/, testdata/, spec/, m4/, vendor/ or gradle/wrapper/: a file with an archive, executable or wasm signature (any extension), a random-looking file over 100 KB, or a symlink out of the repo; or m4/configure/*.am text that decodes and evaluates, or a changed gradle wrapper jar. Misses payloads elsewhere and text-encoded ones under 100 KB. Friction, not a security boundary.

## What it solves

A payload hidden in a test file is how the xz backdoor reached the build (a corrupt-looking xz test file, extracted by an m4 macro at configure time). Reviewers read source, not binaries, and tests/, fixtures/, testdata/ and vendor/ are where unreadable files are expected. This gate reads each changed file in those paths by its first bytes, whatever its name, and also flags a random-looking file over 100 KB, a symlink that leaves the repository, build text (m4, configure, Makefile.am) that decodes and evaluates, and a changed gradle wrapper jar with no new distributionSha256Sum. It warns while its false-positive rate is measured.

## How it works

A guard script, `implementations/opaque-blob-guard-gate.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
binary_or_archive_in(tests|fixtures|testdata|spec|m4|vendor|gradle/wrapper): avoid; if_required: state(purpose), list(sha256+path in .chock/blob-allowlist.txt), person_commits
prefer: generate_in_test_setup | pinned_checksummed_download; never decode_and_eval(test_file)
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/opaque-blob-guard/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add opaque-blob-guard
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/opaque-blob-guard  <your-repo>/.agents/policies/opaque-blob-guard
cd <your-repo> && chock sync --repo .
```

## Customising it

The signatures, scoped folders, entropy limits, build-text patterns and the known gradle wrapper hashes (empty by default, a list of lowercase sha256) live in `implementations/data/*.json`. A file that must stay is listed as `<sha256>  <path>` in `.chock/blob-allowlist.txt`: both must match, one malformed line ignores the whole list, and an agent's own change cannot approve its own blob (only entries already in HEAD count). Keep that file under code-owner review.

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
