---
name: This policy is wrong
about: A policy blocks what it should allow, allows what it should block, or claims too much
labels: bug
---

**Policy id** (e.g. `scan-secrets`):

**Which is it?**

- [ ] Misses something it claims to catch (false negative)
- [ ] Blocks something it should allow (false positive — a gate that cannot be satisfied gets disabled)
- [ ] Claims more enforcement than it delivers (labelled `enforced*` but does not exit non-zero)

**Reproduction** — the staged content, branch, or command, and what the gate did:

**What should have happened:**

**Eval case** (optional, and the most useful thing you can add) — the case in
`base/<id>/evals/suite.yaml` shape that would fail today:
