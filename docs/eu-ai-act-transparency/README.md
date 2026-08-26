# EU AI Act — Transparency

`eu-ai-act-transparency` · rule · advises

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` (`enforcement: advise`) |
| **Mechanism** | rule text |
| **Reaches** | `advisory` — an agent reads it and may or may not follow it |
| **Compiles to** | `ambient-rule` |
| **Eval cases** | 6 total, 0 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Keep EU AI Act Article 50 duties in the code: disclose to a person that they are interacting with an AI system, mark generated audio, image, video, and text in a machine-readable format, and label deepfakes. Use when adding a chatbot or assistant surface, a generation endpoint, or an export path for model output. Do NOT use for assistive editing that does not substantially alter the input, or for internal batch jobs with no human recipient.

## What it solves

Article 50 applies from August 2026 regardless of risk tier, and it is the one obligation that lives in code an agent touches routinely: the disclosure on a chat surface, the C2PA manifest on a generation endpoint, the provenance field a size optimisation quietly deletes.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
when(code emits AI interaction | synthetic text|image|audio|video to a person): disclose(it is AI) + mark(machine_readable: C2PA|watermark|metadata) + label(deepfake) at the emitting boundary
never(remove|weaken): existing provenance marking; exempt: assistive_editing | no_substantial_alteration; see .agents/policies/eu-ai-act-transparency/references/article-50.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/eu-ai-act-transparency/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add eu-ai-act-transparency
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r compliance/eu-ai-act-transparency  <your-repo>/.agents/policies/eu-ai-act-transparency
cd <your-repo> && chock sync --repo .
```

## Customising it

The marking mechanism is what varies -- C2PA for media, response metadata for text -- so name the one your stack uses rather than leaving the choice open. Leave the exemptions intact: assistive editing and non-substantial alteration are what stop this from firing on every autocomplete and being ignored as a result.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals eu-ai-act-transparency
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`compliance/eu-ai-act-transparency/`](../../compliance/eu-ai-act-transparency/) · [all policies](../README.md)
