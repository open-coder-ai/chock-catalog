---
name: Bug report
about: Something in the catalog's own tooling is broken — a checker, generator, or the adoption path
labels: bug
---

**Not sure this is the right form?**

- A policy blocking what it should allow, allowing what it should block, or claiming more
  enforcement than it delivers → use the **This policy is wrong** template instead (pick it
  from the issue chooser).
- The `chock` CLI itself (install, `chock add`, `chock sync`, the compiler) → the
  [chock repo](https://github.com/open-coder-ai/chock/issues/new/choose) instead.

This form is for the catalog's own tooling — `tools/*.py`, the doc/coverage generators, the
adoption transcript, the CI workflows, or `chock add`/`chock sync` producing wrong output
*specifically for a chock-catalog policy* (as opposed to a CLI defect that would reproduce
against any catalog).

**Which tool:**

**Command run, exactly as typed:**

**Expected output:**

**Actual output** — pasted verbatim, not retyped:

**chock version** (`chock --version`) and OS:
