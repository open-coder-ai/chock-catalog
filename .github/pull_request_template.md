## What

<!-- Which policy, and what changes about the behaviour an adopter sees. -->

## Definition of done

- [ ] `python tools/regen_all.py` ends `== CLEAN`, and everything it regenerated is committed. It
      runs, in order: plugin build per tree, `chock sync` (on drift), `tools/gen_registry.py`,
      the policy docs, coverage matrix, java contract, quickstart.sh, figures and brand card,
      and the transcripts of changed policies; then every CI check -- `chock check` (validate,
      lockfile, every eval), `chock sync --check`, plugin `--check`, `check_registry.py`,
      `check_installed.py`, `check_readme.py`, the `--check` of each generator, `check_console.py`,
      `check_workflows.py`, `check_effects.py`, the a11y checks, `ruff check .`, `ruff format
      --check`, the transcript check, the staged adopter with its OWASP claim, and
      `python -m pytest --cov -n auto` at 100% line and branch coverage
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
