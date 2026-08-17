## What

<!-- Which policy, and what changes about the behaviour an adopter sees. -->

## Definition of done

- [ ] `chock check` clean
- [ ] `chock check --only evals` green
- [ ] `chock sync --repo . --check` clean
- [ ] `python tools/gen_policy_docs.py --check` and `python tools/check_readme.py` pass
- [ ] The policy claims only what it can do — advisory if it does not exit non-zero
- [ ] At least one **authored** eval case that could have failed (derived cases alone do not
      support attestation)

## If this touches `implementations/`

- [ ] I understand this script becomes a git hook that runs on every commit in an adopter's
      repository, and a guard consulted before their agent runs a command
- [ ] The script is read in full by a reviewer, not just the diff
