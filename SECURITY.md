# Security Policy

## Reporting a vulnerability

- **Preferred:** open a private security advisory on this repository
  (GitHub → Security → Advisories → "Report a vulnerability").
- Do **not** open a public issue for an exploitable finding.
- Include the affected policy id, reproduction steps, and impact.

Expect an acknowledgment within 7 days.

Framework vulnerabilities — the compiler, the gate runner, the validator — belong in
[open-coder-ai/chock](https://github.com/open-coder-ai/chock/security), not
here. This repository is content.

## What counts as a vulnerability here

This is a policy catalog, so the interesting failures are not crashes:

- **A gate that does not block what it claims to block.** A `scan-secrets` pattern that
  misses a common credential format, or a `protect-main-branch` gate that a plausible
  branch name slips past. An overstated policy is the failure mode this catalog cares most
  about — it is worse than a missing one, because someone is relying on it.
- **A gate that cannot be satisfied.** A guard with no path to a passing commit gets
  disabled within a week, which removes the control entirely.
- **Malicious or unsafe content in a guard script.** See below.

A policy correctly labelled `advisory` that an agent ignores is **not** a vulnerability.
That is what advisory means, and the README says so up front.

## This catalog distributes executable content

`base/<id>/implementations/*.sh` is not documentation. Installed via `chock add`, it
becomes:

- a **git hook** that runs on every commit in the adopter's repository, and
- a **guard** consulted before the adopter's coding agent executes a command.

So a change to a guard script in this repository runs on other people's machines.

**For reviewers:** treat any PR touching `implementations/` as a code-execution change.
Read the whole script, not the diff hunk. The criteria are written down in
[docs/review-criteria/](docs/review-criteria/), and CI runs each guard in a throwaway
workspace to check its declared `effects` against what it actually writes — but that
covers only the argv its eval suite exercises, so it narrows the reading rather than
replacing it.

**For adopters:** `chock add` fetches over `git clone` and is trust-on-first-use.
There is no signing key and no trust root, so pin and verify when the catalog is not one you
control:

```bash
chock add scan-secrets --ref v1.0.0 --verify-sha <sha256>
```

`add` prints the resolved commit and content hash and records them in `chock.lock`;
`chock check --only verify` re-checks them later. The full trust model, including what it does not
cover, is in the framework's
[SECURITY.md](https://github.com/open-coder-ai/chock/blob/main/SECURITY.md).

## Known limits, stated rather than implied

- **`git commit --no-verify` skips every git hook**, and therefore every enforced policy
  here. `block-no-verify` refuses the flag on Claude Code, before the command runs; on other
  agents, and for a human at a terminal, nothing stops it.
- **Git hooks live in `.git/hooks`, which is not cloned.** A fresh clone of an adopting repo
  enforces nothing until someone runs `chock sync`.
- **Seven of the twelve policies are advisory.** They compile to text an agent reads and may
  or may not follow. Their eval cases report as `skipped`, never as passing.
