---
name: Evidence report
about: Replay a policy's eval suite and paste what actually happened
labels: evidence
---

Every policy's claim rests on `evals/suite.yaml` — a set of cases with an expected verdict,
`block` or `allow`. A case nobody re-ran is just a claim. Replaying one, or all of them, and
pasting the real output closes that gap:

```bash
chock check --only evals --repo .
```

for every installed policy, or reproduce a single case by hand in a throwaway repo:

```bash
git init -q /tmp/probe && cd /tmp/probe
chock init . && chock add <policy-id> && chock sync --repo .
# then create the exact input the case in base/<policy-id>/evals/suite.yaml describes,
# and run the commit or tool call it expects to trigger
```

Please paste the terminal output as it printed, not retyped or summarized — a transcript
that cannot be verified is exactly as persuasive, and exactly as useless, as one that is wrong.

**Policy id** (e.g. `scan-secrets`):

**Case replayed** — the `id` from `evals/suite.yaml`, or the new input you tried if it isn't
in the suite yet:

**Expected verdict** (`block` or `allow`, per the case or per the manifest's `gate`):

**Command run, exactly as typed:**

**Output, pasted verbatim:**

```
paste here
```

**Did it match the expected verdict?**

- [ ] Yes — this is a confirmation that the claim holds.
- [ ] No — the guard's actual behavior disagreed with what the suite (or manifest) claims.

**chock version** (`chock --version`) and OS:

**Anything surprising** — a case that passed for the wrong reason, a message that doesn't
match what the gate actually checked, a `content_regex` that caught more or less than
expected. This is the most useful part of the report:
