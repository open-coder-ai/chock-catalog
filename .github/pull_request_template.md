## What

<!-- Which policy, and what changes about the behaviour an adopter sees. -->

## Definition of done

- [ ] `chock check` clean
- [ ] `chock check --only evals` green
- [ ] `chock sync --repo . --check` clean
- [ ] `python tools/gen_policy_docs.py --check` and `python tools/check_readme.py` pass
- [ ] `ruff check .` clean and `python -m pytest --cov` green, at 100% line and branch coverage
- [ ] Every rule added or changed has pytest cases in both directions: refused, and silent on
      the correct form
- [ ] Every java-security rule added or changed cites its CWE (where MITRE has one) and a
      verified reference: CVE, vendor security docs, OWASP, or the analyser rule it mirrors
- [ ] The policy claims only what it can do — advisory if it does not exit non-zero
- [ ] At least one **authored** eval case that could have failed (derived cases alone do not
      support attestation)

## If this touches `implementations/`

- [ ] I understand this script becomes a git hook that runs on every commit in an adopter's
      repository, and a guard consulted before their agent runs a command
- [ ] The script is read in full by a reviewer, not just the diff
