---
name: firecrawl-fallback-only
description: "trigger: web research where a direct fetch fails, is blocked, or needs JS rendering. avoid: reaching for the Firecrawl connector as the default fetch path."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Firecrawl Fallback Only

trigger: web research where a direct fetch fails, is blocked, or needs JS rendering. avoid: reaching for the Firecrawl connector as the default fetch path.

```
web_access: prefer(native: WebFetch|WebSearch|curl); firecrawl_connector: fallback_only
use_firecrawl_if: research_task & direct_fetch(failed|blocked|js_only|rate_limited); never(default): firecrawl; on_use: note_fallback_reason
```

This skill is advisory: the client reading it has no mechanism to enforce it, and this policy stays advisory even when compiled by `chock` -- it ships rule text, not a blocking hook. See https://github.com/open-coder-ai/chock
