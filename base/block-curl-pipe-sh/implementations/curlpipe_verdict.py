"""Verdicts, messages, and the plain-text readings used when the structure cannot be trusted."""

import re

from curlpipe_rules import STRONG

BLOCK, ASK = 1, 3
Verdict = tuple[int, str] | None
ADVICE = "Download it to a file, read or verify it (sha256sum -c, gpg --verify), then run it as a separate step."
#: Any downloader, socket reader or URL: what a body has to mention to be worth reading again.
FETCH_HINT = re.compile(
    r"(?<![\w-])(?:curl|wget2?|fetch|aria2c|lynx|https?|xh|curlie|iwr|irm|invoke-webrequest|invoke-restmethod"
    r"|start-bitstransfer|nc|ncat|netcat|socat|telnet)(?![\w-])|/dev/(?:tcp|udp)/|downloadstring|urlopen|urllib",
    re.IGNORECASE,
)
_CRUDE_FETCH = re.compile(
    r"(?<![\w.-])(?:curl|wget2?|aria2c|lynx|xh|curlie|iwr|irm|invoke-webrequest|invoke-restmethod|nc|ncat|socat)"
    r"(?![\w-])|downloadstring|/dev/tcp/",
    re.IGNORECASE,
)
_CRUDE_RUN = re.compile(
    r"(?<![\w./-])(?:sh|bash|zsh|dash|ksh|ash|mksh|fish|csh|tcsh|busybox|(?:python|pypy)[0-9.]*|perl|ruby|node"
    r"|nodejs|php|lua|deno|bun|pwsh|powershell|iex|invoke-expression|eval|source|su)(?![\w-])|\$\{?shell\b"
    r"|(?:^|[\s;&|(])\.\s",
    re.IGNORECASE,
)
_PS_FETCH = re.compile(
    r"(?<![\w-])(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget|start-bitstransfer)(?![\w-])"
    r"|net\.webclient|downloadstring|downloaddata|downloadfile",
    re.IGNORECASE,
)
_PS_RUN = re.compile(
    r"\|\s*&?\s*(?:iex|invoke-expression)(?![\w-])|(?<![\w-])(?:iex|invoke-expression)\s*(?:[($'\"]|-c)"
    r"|\[scriptblock\]::create",
    re.IGNORECASE,
)


def refuse(what: str) -> Verdict:
    return BLOCK, f"BLOCKED: {what}, so remote code would run unread. {ADVICE}"


def wired(strength: int, into: str) -> Verdict:
    if strength == STRONG:
        return refuse(f"a network download is wired into {into}")
    return ASK, (
        f"CONFIRM: a raw network read (nc, socat, /dev/tcp or an interpreter one-liner) is wired into {into}. "
        "Ask the person to confirm; better, save it to a file and read it first."
    )


def strongest(found: list[Verdict]) -> Verdict:
    """A block wins over an ask, which wins over silence."""
    real = [v for v in found if v]
    return next((v for v in real if v[0] == BLOCK), real[0] if real else None)


def crude(text: str) -> Verdict:
    """Fail closed when the structure is lost: a downloader and an interpreter named anywhere is a refusal."""
    if _CRUDE_FETCH.search(text) and _CRUDE_RUN.search(text):
        return refuse(
            "this command could not be parsed (unbalanced quote, trailing backslash or nesting too deep) "
            "and names a downloader and a shell or interpreter"
        )
    return None


def powershell(text: str) -> Verdict:
    if _PS_FETCH.search(text) and _PS_RUN.search(text):
        return refuse("a PowerShell download is passed to Invoke-Expression (iex)")
    return None
