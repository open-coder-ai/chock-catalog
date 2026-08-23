---
name: eu-ai-act-prohibited-practices
description: "Refuse to implement AI practices banned outright by EU AI Act Article 5: social scoring, untargeted facial-image scraping, emotion inference at work or school, biometric categorisation by sensitive traits, profiling-only predictive policing, subliminal or vulnerability-based manipulation, real-time remote biometric ID in public spaces, and NCII/CSAM generators. Use when a feature request names any of these. Do NOT use for lawful biometric verification, fraud detection, or safety/medical emotion detection."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# EU AI Act — Prohibited Practices

Refuse to implement AI practices banned outright by EU AI Act Article 5: social scoring, untargeted facial-image scraping, emotion inference at work or school, biometric categorisation by sensitive traits, profiling-only predictive policing, subliminal or vulnerability-based manipulation, real-time remote biometric ID in public spaces, and NCII/CSAM generators. Use when a feature request names any of these. Do NOT use for lawful biometric verification, fraud detection, or safety/medical emotion detection.

```
never(implement|assist): social_scoring | untargeted_face_scraping | emotion_inference(workplace|education) | biometric_categorisation(sensitive_traits) | predictive_policing(profiling_only) | subliminal_manipulation | vulnerability_exploitation(age|disability|socioeconomic) | realtime_remote_biometric_id(public_space) | NCII | CSAM
on_request: refuse + cite(EU AI Act Art 5) + offer(compliant_alternative); see .agents/policies/eu-ai-act-prohibited-practices/references/article-5.md
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` becomes a git hook that exits non-zero. See https://github.com/open-coder-ai/chock
