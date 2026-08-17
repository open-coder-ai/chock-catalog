# Review criterion: effects honesty

**A policy claims only what it does.** Its manifest's `effects` must match what its mechanism
actually does when run.

First of the catalog's review criteria, and first deliberately. This repository distributes
executable content: `implementations/*.sh` becomes a git hook on every commit in an adopter's
repository and a guard consulted before their agent runs a command. A framework bug is a bug in
our repo; a mislabelled policy is a wrong claim running on someone else's machine.

## What `effects` means

From `spec/methodology.md` in the framework:

| Value | Meaning |
| :--- | :--- |
| `read_only` | reads repo/state but does not write |
| `writes_workspace` | writes inside the adopter's workspace |
| `writes_external` | writes outside it — API, PR, git remote |
| `irreversible` | cannot be undone without an external undo |
| `reads_private`, `network` | informational |

`writes_external` and `irreversible` trigger EFF-1: the policy must carry
`enforcement: verify|block` and `approval.required: true`. So the declaration is not
paperwork — it decides whether a human is asked before the thing runs.

## The defect this exists for

`protect-main-branch` blocked commits on `release/1.0` while its block message named only
`main` and `master`. Declared behaviour and actual behaviour disagreed, in shipped content, and
it survived every check the repo had at the time.

Nothing there was careless. The message was accurate when written, config resolution later
changed what the gate enforced, and no mechanism tied the two together. That is the shape of
this failure: not a lie, a drift.

## What is already mechanical

Do not re-litigate these in review; CI decides them:

| Claim | Checked by |
| :--- | :--- |
| `enforcement: block\|verify` has a gate or guard | framework `validate` (block-needs-gate) |
| Gate `kind` and `params` conform | framework `validate` (gate params) |
| Declared gate behaviour matches its suite | `chock check --only evals` |
| Registry `mechanism` / `enforces` labels are derived, not asserted | CI's registry step |
| Quoted terminal output matches what the tools print | `tools/check_console.py` |
| A `read_only` guard does not write | `tools/check_effects.py` |

## `check_effects.py`, and what it does not cover

It **observes the effect** rather than reading the source. The guard is run inside a throwaway
workspace and home directory seeded with canary files, once per `execute.command` in the
policy's eval suite, and the filesystem is hashed before and after. Any creation, modification
or deletion contradicts a `read_only` declaration.

Behavioural rather than a lint on purpose. `block-destructive.sh` contains `rm` inside a `case`
pattern and `echo … >&2`; a source lint has to decide whether either is a write, and the false
positives it produces are how a check gets deleted. Running the thing asks the question the
manifest actually answers.

Deliberate gaps, so a green check is not read as more than it is:

- **Only the argv the eval suite exercises.** A write on an untested path is not detected.
  Extending a guard means extending its eval cases; the check's reach grows with the suite.
- **`TMPDIR` is redirected outside the observed tree.** A guard using `mktemp` is not writing
  in the sense `read_only` is about, and failing it would be an over-block.
- **Gate policies are excluded.** Their behaviour is the framework's vendored runner, not
  catalog content.
- **Two policies ship guards today.** The other ten have nothing to run.

## What a reviewer still has to judge

The part no check reaches, and therefore the part review is for:

1. **Does the message describe what the mechanism does?** Compare the resolved block message
   against the gate's actual parameters — the `release/1.0` case. `check_console.py` catches
   this only where the message is quoted in the README.
2. **Can the guard be satisfied?** A guard that blocks a legitimate command gets disabled
   within a week, and a disabled guard enforces nothing. Every trigger case needs a
   negative-trigger sibling that must still pass.
3. **Does the eval suite exercise the paths that matter?** Derived cases alone do not support
   attestation; at least one authored case must be able to fail.
4. **Is the claimed tier the honest ceiling?** A policy that does not exit non-zero is
   advisory, whatever the manifest says.

## Reviewing a change to a guard

Read the whole script, not the diff hunk — the [SECURITY.md](../../SECURITY.md) rule. A guard
is judged by what it does when it runs, and a three-line diff can change that completely.

Expect this review to be slower than one on a docs fix or an advisory rule. That is the control
working.
