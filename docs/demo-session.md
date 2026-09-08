# The full blocked-commit session

This is the untrimmed transcript behind the [hero GIF](assets/demo.gif) and the shortened
excerpt in the README's [_It actually blocks the commit_](../README.md#it-actually-blocks-the-commit)
section. Captured by actually running these commands in a throwaway repository — not written
to look like it was. Two things are elided and marked `…`: absolute paths, and the resolved
catalog commit `add` prints, which changes with every commit to this repo.

```console
$ chock init .
Installed pre-commit dispatcher to …/.git/hooks/pre-commit
No git-pre-commit.sh policies found; pre-commit dispatcher unchanged
Installed pre-merge-commit dispatcher to …/.git/hooks/pre-merge-commit
No git-pre-commit.sh policies found; pre-merge-commit dispatcher unchanged
Installed pre-push dispatcher to …/.git/hooks/pre-push
No git-pre-push.sh policies found; pre-push dispatcher unchanged
Registered SessionStart arm hook in .claude/settings.json
INDEX.md: ~257 tokens (chars/4, max 2000)
Implementation registered at …/.git/hooks/pre-commit.d/99-chock-validate
[PASS] All checks passed.
Initialized Chock in …
Agents: AGENTS.md + claude, copilot, gemini
Skills: eval, optimize, policy-init, validate (refresh with `chock install-skills .`)
Policies: none. This repo enforces nothing yet.
  1. copy a policy folder from https://github.com/open-coder-ai/chock-catalog (base/<id>/) into .agents/policies/<id>/
  2. chock sync --repo .
Verify anytime with:  chock check --only verify

$ chock add scan-secrets
Added scan-secrets to .agents/policies/scan-secrets
  from https://github.com/open-coder-ai/chock-catalog at …
  sha256 6f8285363e7795bf2cedb78a449b7f5b49d7b188047a7802c12fbdc7f63cad4b
  (unpinned: this was the default branch. Pin with --ref, or --verify-sha 6f8285363e7795bf2cedb78a449b7f5b49d7b188047a7802c12fbdc7f63cad4b)
INDEX.md: ~352 tokens (chars/4, max 2000)
Compiled. Run `chock sync --repo .` to activate commit-time enforcement.

$ chock add protect-main-branch
Added protect-main-branch to .agents/policies/protect-main-branch
  from https://github.com/open-coder-ai/chock-catalog at …
  sha256 316bd80a2fdbeb098f8477503af8c9e0977cf11be4e32572d87014ef062e055d
  (unpinned: this was the default branch. Pin with --ref, or --verify-sha 316bd80a2fdbeb098f8477503af8c9e0977cf11be4e32572d87014ef062e055d)
INDEX.md: ~389 tokens (chars/4, max 2000)
Compiled. Run `chock sync --repo .` to activate commit-time enforcement.

$ chock sync --repo .
Installed pre-commit dispatcher to …/.git/hooks/pre-commit
Registered 2 pre-commit policy implementation(s)
Installed pre-merge-commit dispatcher to …/.git/hooks/pre-merge-commit
Registered 2 pre-merge-commit policy implementation(s)
Installed pre-push dispatcher to …/.git/hooks/pre-push
Registered 1 pre-push policy implementation(s)
INDEX.md: ~389 tokens (chars/4, max 2000)
Recompiled 2 policies
protect-main-branch:
  claude: enforced-at-commit
  copilot: enforced-at-commit
  gemini: enforced-at-commit
scan-secrets:
  claude: enforced-at-commit
  copilot: enforced-at-commit
  gemini: enforced-at-commit
```

Now try to commit a secret, on a feature branch:

```console
$ git commit -m "add config"
Potential secret detected in this change. Remove credentials and rotate any exposed keys. At commit, add '# pragma: allowlist secret' on the same line only for documented test fixtures; the pragma is NOT honored at tool-use, where the scanned text is a live tool argument an appended token could neutralize.
  - config.py: content pattern
# exit 1
```

Remove the key, change nothing else:

```console
$ git commit -m "add config"
== validate
[PASS] All checks passed.
[feature/demo (root-commit) 432b2db] add config
 1 file changed, 2 insertions(+)
 create mode 100644 config.py
# exit 0
```

And on `main`:

```console
$ git commit --allow-empty -m notes
Direct commits/pushes to a protected branch (main|master) are blocked. Create a feature branch and open a pull request.
  - main
# exit 1
```

The protected branches in that message are not hard-coded — they are the ones the gate is
actually enforcing. Set `chock.defaults.protected_branches` to `[main, master, release/*]`
and the same commit on `release/1.0` reports `(main|master|release/*)`. A block message that
names a different set from the gate is how an adopter learns to distrust the tool.

Note the third block: the gate is not "block everything scary" — it passed the moment the
secret was gone. A guard that cannot be satisfied gets disabled within a week.
