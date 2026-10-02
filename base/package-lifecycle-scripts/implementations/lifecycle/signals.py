"""Does a hook body download, decode or evaluate code? Shared by every file family; text in, a reason out."""

from __future__ import annotations

import re

#: Download tools and URLs (roadmap NP04: fetch tools, certutil, URLs). Bounded on both sides so
#: `curlew` or `my-wget-helper` is not one (a path prefix such as /usr/bin/curl is); .NET and
#: PowerShell names are case-insensitive like the shell.
FETCH = re.compile(
    r"(?i)(?<![\w$-])(?:curl|wget2?|aria2c|lynx|invoke-webrequest|iwr|irm|invoke-restmethod|start-bitstransfer"
    r"|bitsadmin|certutil)(?:\.exe)?(?![\w-])"
    r"|(?i:\b(?:downloadstring|downloadfile|downloaddata|webclient|httpclient|webrequest)\b)"
    r"|\b(?:https?|ftps?)://"
    r"|(?<![\w.$])fetch\s*\(|\bhttps?\.(?:get|request)\s*\(|\brequire\(\s*['\"](?:node:)?https?['\"]\s*\)"
)
#: Base64 decoding, in a shell, in JS or in PowerShell (`-EncodedCommand <blob>`).
DECODE = re.compile(
    r"(?i)\bbase64\b[^|;&\n]*?\s(?:-d|-D|--decode)(?![\w-])|\batob\s*\(|frombase64string|b64decode"
    r"|\bBuffer\.from\([^)]*['\"]base64['\"]|(?<![\w-])-e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/]{20,}={0,2}"
    r"|\bxxd\s+(?:-\w+\s+)*-r\b|\bopenssl\s+(?:enc|base64)\b[^|;&\n]*\s-d\b"
)
#: Inline code: interpreter -e/-c/-r/-p flags, eval, PowerShell, child_process, Function constructors.
EVAL = re.compile(
    r"(?i)(?<![\w$-])(?:node|nodejs|bun)(?:\.exe)?(?:\s+--?[\w-]+(?:=\S+)?)*?\s+(?:-e|--eval|-p|--print|-pe)(?![\w-])"
    r"|(?<![\w$-])deno\s+eval\b"
    r"|(?<![\w$-])(?:python[\d.]*|py)(?:\.exe)?(?:\s+-[a-zA-Z]+)*?\s+-[a-zA-Z]*c(?![\w-])"
    r"|(?<![\w$-])(?:perl|ruby|lua)(?:\.exe)?(?:\s+-[a-zA-Z]+)*?\s+-[a-zA-Z]*[eE](?![\w-])"
    r"|(?<![\w$-])php(?:\.exe)?(?:\s+-\w+)*?\s+-r(?![\w-])"
    r"|(?<![\w$-])eval(?![\w-])|(?<![\w$-])(?:powershell|pwsh)(?:\.exe)?(?![\w-])"
    r"|(?<![\w$-])(?:iex|invoke-expression)(?![\w-])|\bchild_process\b|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\("
)

LABELS = (
    (FETCH, "downloads or names a URL"),
    (DECODE, "decodes base64"),
    (EVAL, "evaluates inline code, PowerShell or child_process"),
)


def danger(text: str) -> str | None:
    """Why a hook body is fetch-exec class, or None when it holds none of the roadmap's signals."""
    for pattern, label in LABELS:
        if pattern.search(text):
            return label
    return None
