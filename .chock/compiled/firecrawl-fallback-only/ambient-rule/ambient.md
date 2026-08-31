<!-- chock:hooks:start (compiled by chock -- edit .agents/policies/firecrawl-fallback-only/) -->
```
web_access: prefer(native: WebFetch|WebSearch|curl); firecrawl_connector: fallback_only
use_firecrawl_if: research_task & direct_fetch(failed|blocked|js_only|rate_limited); never(default): firecrawl; on_use: note_fallback_reason
```
<!-- chock:hooks:end -->
