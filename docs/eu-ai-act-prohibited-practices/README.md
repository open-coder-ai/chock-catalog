# EU AI Act — Prohibited Practices

`eu-ai-act-prohibited-practices` · rule · advises

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

Refuse to implement AI practices banned outright by EU AI Act Article 5: social scoring, untargeted facial-image scraping, emotion inference at work or school, biometric categorisation by sensitive traits, profiling-only predictive policing, subliminal or vulnerability-based manipulation, real-time remote biometric ID in public spaces, and NCII/CSAM generators. Use when a feature request names any of these. Do NOT use for lawful biometric verification, fraud detection, or safety/medical emotion detection.

## What it solves

Feature requests for things the AI Act bans outright -- a trust score reused across contexts, emotion inference over employees, a face-image scraper -- arriving as ordinary tickets. They are in force now, and the failure mode is an agent building the thing competently because nobody framed it as a legal question.

## How it works

There is no mechanism. The rule text is compiled into the agent's ambient context:

```text
never(implement|assist): social_scoring | untargeted_face_scraping | emotion_inference(workplace|education) | biometric_categorisation(sensitive_traits) | predictive_policing(profiling_only) | subliminal_manipulation | vulnerability_exploitation(age|disability|socioeconomic) | realtime_remote_biometric_id(public_space) | NCII | CSAM
on_request: refuse + cite(EU AI Act Art 5) + offer(compliant_alternative); see .agents/policies/eu-ai-act-prohibited-practices/references/article-5.md
```

It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.

## Which primitive it becomes

An **ambient rule**. `recompile` writes `.chock/compiled/eu-ai-act-prohibited-practices/ambient-rule/ambient.md`, and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text reaches the agent's context and that is the entire mechanism.

## Installing it

```bash
chock add eu-ai-act-prohibited-practices
chock sync --repo .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r compliance/eu-ai-act-prohibited-practices  <your-repo>/.agents/policies/eu-ai-act-prohibited-practices
cd <your-repo> && chock sync --repo .
```

## Customising it

The ban list tracks Article 5 and should be edited only to follow the law, not to fit a roadmap. The carve-outs are the part worth reading before you narrow anything: biometric verification, fraud detection, and safety or medical emotion detection are lawful, and a rule that refuses them teaches the agent to route around it.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals eu-ai-act-prohibited-practices
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`compliance/eu-ai-act-prohibited-practices/`](../../compliance/eu-ai-act-prohibited-practices/) · [all policies](../README.md)
