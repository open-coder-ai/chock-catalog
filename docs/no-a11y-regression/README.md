# No Accessibility Regression Rule

`no-a11y-regression` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: block`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 13 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

trigger: remediating accessibility, editing markup, emptying or removing an alt, aria-label, label or lang that an element already had, deleting a flagged element. avoid: breaking a requirement the previous revision met; interrupting a correct fix.

## What it solves

An agent remediating accessibility can make it worse while the report says it improved. Emptying an existing `alt` to `alt=""` produces no violation at all -- empty alt is the correct marking for a decorative image, so every checker passes it -- and deleting a flagged element scores as a resolved violation. Both transitions are invisible to any tool that diffs violations rather than state, which is every tool in this space.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
never(break): name|lang an element already had -- remove, empty(alt=""), aria-hidden, role=presentation|none; never(resolve_violation_by): delete(element)
on(name_added): record, never_ask; alt="" asserts decorative and only its author may retract a description; present -> present (reworded label) is a copy decision, stay silent
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/no-a11y-regression/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add no-a11y-regression
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/no-a11y-regression  <your-repo>/.agents/policies/no-a11y-regression
cd <your-repo> && chock sync --repo .
```

## Customising it

The rule names the two transitions and the silence rule; it carries no element table, because no conformance claim is made. Run a checker for detection, and keep the review of added names in the pull request where a person already reads the diff. The mechanism that decides these transitions deterministically is prototyped at open-coder-ai/org-plan, `prototypes/a11y-guard` -- it is not wired as a guard here, because no adapter passes file content to one.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals no-a11y-regression
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/no-a11y-regression/`](../../base/no-a11y-regression/) · [all policies](../README.md)
