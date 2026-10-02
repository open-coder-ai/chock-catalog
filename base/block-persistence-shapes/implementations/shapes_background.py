"""Downloaders run detached: the parser drops a trailing `&`, `nohup` and `setsid`, so they are read from the text."""

import shlex

from chock_shellparse import commands

SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh"))
DEPTH = 3


def segments(text: str) -> list[tuple[str, bool]]:
    """(command text, whether a lone `&` follows it), split at ; newline && || and a lone &, outside quotes."""
    out: list[tuple[str, bool]] = []
    buf: list[str] = []
    quote, i = "", 0
    while i < len(text):
        char = text[i]
        if quote:
            buf.append(char)
            if char == "\\" and quote == '"':
                buf.append(text[i + 1 : i + 2])
                i += 1
            elif char == quote:
                quote = ""
        elif char == "\\":
            buf.append(text[i : i + 2])
            i += 1
        elif char in "'\"":
            quote = char
            buf.append(char)
        elif char in ";\n" or text[i : i + 2] in ("&&", "||"):
            out.append(("".join(buf), False))
            buf = []
            i += char in "&|"
        elif char == "&" and text[i - 1 : i] not in ("<", ">", "|") and text[i + 1 : i + 2] != ">":
            out.append(("".join(buf), True))
            buf = []
        else:
            buf.append(char)
        i += 1
    return [*out, ("".join(buf), False)]


def payloads(words: list[str]) -> list[str]:
    """Scripts handed to `sh -c` or `eval` among the words."""
    found = []
    for i, word in enumerate(words):
        if word == "eval":
            found.append(" ".join(words[i + 1 :]))
        elif word.rsplit("/", 1)[-1] in SHELLS:
            flags = [
                j
                for j in range(i + 1, len(words) - 1)
                if words[j][:1] == "-" and words[j][1:2] != "-" and "c" in words[j]
            ]
            found += [words[flags[0] + 1]] if flags else []
    return found


def detached(text: str, tab: dict, depth: int = 0) -> str:
    """The downloader a command line starts in the background or under nohup/setsid, or ''."""
    for segment, background in segments(text):
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
        started = [cmd.name for cmd in commands(segment) if cmd.name in tab["downloaders"]]
        if started and (background or set(words) & set(tab["detachers"])):
            return started[0]
        for inner in payloads(words) if depth < DEPTH else []:
            found = detached(inner + (" &" if background else ""), tab, depth + 1)
            if found:
                return found
    return ""
