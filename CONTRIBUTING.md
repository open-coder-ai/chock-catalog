# Contributing

Issues and PRs welcome, including "this policy is wrong". **Especially** that one — an
overstated policy is worse here than a missing one.

## The three rules

All are mechanical, and all are checked by CI rather than by a reviewer's memory.

**1. A policy claims only what it can do.** If it does not exit non-zero, it is advisory,
and the tooling labels it that way whatever the manifest says. Twenty of the thirty-two
policies here are advisory, and the README says so in its third paragraph rather than its
appendix. Do not raise a claim your mechanism cannot support.

**2. Evals are the argument.** A gate whose declared behaviour does not match its suite
fails CI. Derived cases alone are not enough — attestation needs at least one authored case
that could have failed.

**3. A new or changed policy ships its adoption transcript.** Run

```bash
python tools/gen_adoption_transcript.py --policy <your-policy-id>
```

and commit `docs/<id>/adoption.md` in the same PR. The tool adopts your policy into an
empty repository — init, copy, recompile, install-hooks, validate, eval — and records what
the tools printed. CI re-runs the same adoption and diffs: pasted or edited output fails,
because the transcript's value is that it *cannot* be written by hand. A PR touching a
policy without its transcript fails with exactly this command.

## Good first contributions

Roughly in order of usefulness:

1. **Turn an advisory policy into an enforced one.** Any of the twenty that can be expressed
   as a `content_regex`, `forbidden_ref` or `dependency_allowlist` gate is a strict upgrade —
   and the eval suite already describes the behaviour you would need to satisfy. Where only a
   slice is greppable, add a narrow sibling gate instead of promoting the rule: the
   `code-safety`/`scan-secrets` and `owasp-asi05`/`block-unsafe-code-execution` splits are
   the pattern.
2. **Add token formats to `scan-secrets`.** Every vendor has a prefix. Generic scanners miss
   the internal ones.
3. **Extend `block-destructive-commands`** with the commands your stack actually has —
   `helm uninstall`, `aws s3 rm --recursive`, `dropdb`.
4. **Write a policy for your domain.** `chock init` installs a `policy-init` skill;
   ask your agent to run it and it scaffolds a conformant folder.

## Local loop

```bash
git clone https://github.com/open-coder-ai/chock-catalog
cd chock-catalog

pip install chock                 # or: pip install git+https://github.com/open-coder-ai/chock

chock check                  # conformance
chock check --only evals               # replay every gate
chock sync --repo . --check  # compiled artifacts match their manifests

chock plugin build --repo . --policies-dir base --check   # Agent Plugins output is current

python tools/gen_policy_docs.py --check  # docs match the manifests they describe
python tools/check_readme.py             # README counts match what is in base/
python tools/check_console.py            # quoted terminal output matches what the tools print
python tools/check_workflows.py          # no workflow trigger can hand fork code our secrets
python tools/gen_adoption_transcript.py --check --base origin/main
                                         # transcripts of touched policies reproduce from empty repos
python tools/check_effects.py            # a read_only guard does not actually write
```

The last five matter more than they look. The factual half of every policy page is derived
from `base/<id>/`, so a stale doc is an overclaim published where adopters read first.

`check_console.py` is there because quoted terminal output broke twice: a block message that
read `(main/master)` while the gate it described blocked `main|master`, and a transcript
labelled "captured by running these commands" that had gone stale. A reader cannot verify a
transcript, which is exactly what makes it persuasive — and what makes a wrong one worse than
a wrong number. If you change a gate message, re-run the commands and paste the real output.

## Review criteria

What a reviewer checks, and what CI checks instead, is written down rather than held in
one person's head — [docs/review-criteria/](docs/review-criteria/).

The first is [effects honesty](docs/review-criteria/effects-honesty.md): a policy claims
only what it does. `check_effects.py` enforces the mechanical half by *running* each
guard in a throwaway workspace and hashing the filesystem either side — a `read_only`
declaration over a guard that writes is a wrong claim executing on someone else's
machine. The page also lists the four things it deliberately does not cover, which are
the things review is actually for.

## Reviewer evidence (optional)

`chock review emit` runs every check above and records the results, so a reviewer can see
what was already machine-checked and spend their attention on what was not:

```bash
chock review emit --base origin/main --kind human --by "<your name>"
```

Then add the judgement claims a machine cannot make — under `attested`, each with the `basis`
you actually used. CI re-derives the `verified` half and prints the `attested` half under
**NOT verified**, because a claim nobody re-ran must not look checked.

Optional today. Nothing is rejected for lacking it, and a PR that skips it is a normal PR.

## Layout

One folder per policy under `base/<id>/`:

```
base/<id>/
  manifest.yaml           identity, and either a gate or rule text
  implementations/*.sh    guard script, for policies consulted before a command runs
  evals/suite.yaml        the cases that decide whether the claim holds
```

`docs/<id>/README.md` is generated — edit `manifest.yaml` and
`docs/policy-prose.yaml`, then run `python tools/gen_policy_docs.py`.

## What CI runs

Two things, kept apart on purpose:

- **What this repo runs** — every `base/` policy, installed in `.agents/policies/` to
  govern the catalog itself: the repo protects itself the same way it asks adopters to.
  The compliance and agentic-security packs stay uninstalled — by their own doctrine they
  only earn their place where they apply. This repo is a Chock adopter, and the first
  commit after adoption was rejected by `protect-main-branch`.
- **What this repo ships** — every published policy, staged into a throwaway repo the way an
  adopter installs them (where CI also re-derives the README's OWASP coverage claim).

Runs fewer than it ships: a catalog should publish more than it is bound by.

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO): a one-line trailer on each commit certifying you have the right to contribute the
change under the project's license (Apache-2.0). Add it with the `-s` flag:

```bash
git commit -s -m "feat(scan-secrets): add vendor token prefixes"
```

CI checks every PR commit for the `Signed-off-by:` trailer. Forgot one?
`git commit --amend -s --no-edit && git push --force-with-lease`
(or `git rebase --signoff main` for several).

## Security

A policy in this catalog is executable content — `implementations/*.sh` becomes a git hook
that runs on every commit in an adopter's repo. Review PRs to guard scripts accordingly. See
[SECURITY.md](SECURITY.md).

[`.github/CODEOWNERS`](.github/CODEOWNERS) routes review for the paths where that matters:
`implementations/`, the CI workflow, the tools CI depends on, and `SECURITY.md` itself. A PR
touching any of them requests review automatically, so a guard script cannot reach `main`
without someone being asked to read it.

Expect a slower review on those paths than on a docs fix or a new advisory rule. Reading a
guard script in full is the control, so it is not something to hurry.

## Code of Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1.

Apache-2.0. By contributing you agree your work is licensed under it.
