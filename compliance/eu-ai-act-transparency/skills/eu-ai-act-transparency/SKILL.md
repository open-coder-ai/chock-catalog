---
name: eu-ai-act-transparency
description: "Keep EU AI Act Article 50 duties in the code: disclose to a person that they are interacting with an AI system, mark generated audio, image, video, and text in a machine-readable format, and label deepfakes. Use when adding a chatbot or assistant surface, a generation endpoint, or an export path for model output. Do NOT use for assistive editing that does not substantially alter the input, or for internal batch jobs with no human recipient."
metadata:
  chock:
    artifact: rule
    enforcement: advise
    coverage_without_chock: advisory
---

# EU AI Act — Transparency

Keep EU AI Act Article 50 duties in the code: disclose to a person that they are interacting with an AI system, mark generated audio, image, video, and text in a machine-readable format, and label deepfakes. Use when adding a chatbot or assistant surface, a generation endpoint, or an export path for model output. Do NOT use for assistive editing that does not substantially alter the input, or for internal batch jobs with no human recipient.

```
when(code emits AI interaction | synthetic text|image|audio|video to a person): disclose(it is AI) + mark(machine_readable: C2PA|watermark|metadata) + label(deepfake) at the emitting boundary
never(remove|weaken): existing provenance marking; exempt: assistive_editing | no_substantial_alteration; see .agents/policies/eu-ai-act-transparency/references/article-50.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
