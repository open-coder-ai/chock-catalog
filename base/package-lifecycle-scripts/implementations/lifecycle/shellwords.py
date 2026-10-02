"""Which files a package-script body runs, read from its shell words; over-approximated on purpose.

A hook that runs a file makes that file part of the install, so editing it alone must be judged. Every
operand of an interpreter command counts (data arguments included); a non-interpreter command counts
only its program, when that is a path. `-c`/`-e` operands are read again as commands.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from functools import lru_cache

INTERPRETERS = frozenset(
    "node nodejs bun deno sh bash zsh dash ksh python python3 py ruby perl php pwsh powershell tsx ts-node lua"  # noqa: SIM905
    " zx babel-node esno esr vite-node jiti sucrase-node ts-node-esm coffee source . cmd".split()
)
#: Words that run the rest of the line: `env X=1 node x.js`, `npx tsx x.ts`, `pnpm exec node x.js`.
WRAPPERS = frozenset("env sudo doas exec nohup time command cross-env npx pnpx bunx run x --".split())  # noqa: SIM905
RUNNERS = frozenset("npm pnpm yarn bun".split())  # noqa: SIM905 -- followed by exec/x/node, also wrappers
KEYWORDS = frozenset("if then else elif fi do done while until for ! { } ( )".split())  # noqa: SIM905
#: Flags whose value is code to run (read again as commands) or a module to load (a file it runs).
INLINE = frozenset(["-e", "--eval", "-p", "--print", "-pe", "-c", "-E", "/c", "/C", "/k", "/K"])
LOADS = frozenset(["-r", "--require", "--import", "--loader", "--experimental-loader"])
#: Flags that take a separate value which is not a file to run.
VALUED = frozenset(["-W", "-X", "-m", "-C", "--max-old-space-size", "--env-file", "--config", "--title"])
SEPARATORS = re.compile(r"&&|\|\||[;|&\n(){}]|\$\(|`")
REDIRECT = re.compile(r"^\d*(?:[<>]{1,2}|&>)&?\d*$")
EXTENSIONS = ("", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", "/index.js", "/index.mjs", "/index.cjs", "/index.ts")
MAX_NESTING = 3


def _words(command: str) -> list[str]:
    """Shell words, quotes removed; redirects (`>log`, `2>&1`) dropped; plain splitting when quoting is broken."""
    command = re.sub(r"\\(?=[\w.-])", "/", command)  # a Windows path separator, not a shell escape
    try:
        raw = shlex.split(command, posix=True)
    except ValueError:
        raw = [w.strip("'\"") for w in command.split()]
    words, skip = [], False
    for word in raw:
        if skip:
            skip = False
        elif REDIRECT.match(word):
            skip = not word.endswith(tuple("0123456789")) or word.endswith(">")
        elif re.search(r"\d*[<>]", word) and not word.startswith(("<", ">")):
            words.append(re.split(r"\d*[<>]", word, maxsplit=1)[0])
        elif not word.startswith(("<", ">")):
            words.append(word)
    return [w for w in words if w]


def _strip_prefix(words: list[str]) -> list[str]:
    """Drop assignments, keywords, wrappers with their flags, and `npm/pnpm/yarn/bun exec|x|node` runners."""
    while words:
        head = words[0]
        if re.match(r"^[A-Za-z_]\w*=", head) or head in KEYWORDS or head in WRAPPERS:
            words = words[1:]
            while words and words[0].startswith("-") and words[0] != "--":
                words = words[1:]
        elif head in RUNNERS and len(words) > 1 and words[1] in ("exec", "x", "node", "dlx"):
            words = words[2:] if words[1] != "node" else words[1:]
        elif head in RUNNERS and len(words) > 1 and words[0] == "yarn" and not words[1].startswith("-"):
            words = words[1:]
        else:
            return words
    return words


@lru_cache(maxsize=256)
def executed(body: str, nesting: int = 0) -> tuple[tuple[str, bool], ...]:
    """(path, primary) for each file the body may run; primary marks a program or an interpreter's first operand."""
    found: list[tuple[str, bool]] = []
    for command in SEPARATORS.split(body):
        words = _strip_prefix(_words(command))
        if not words:
            continue
        program = posixpath.basename(words[0].replace("\\", "/")).lower().removesuffix(".exe")
        if program not in INTERPRETERS:
            if "/" in words[0] or "." in posixpath.basename(words[0]):
                found.append((words[0], True))
            continue
        found += _operands(words[1:], nesting)
    return tuple(found)


def _operands(words: list[str], nesting: int) -> list[tuple[str, bool]]:
    found: list[tuple[str, bool]] = []
    primary, index = True, 0
    while index < len(words):
        word = words[index]
        flag, _, value = word.partition("=")
        if flag in INLINE or flag in LOADS or flag in VALUED:
            value = value or (words[index + 1] if index + 1 < len(words) else "")
            index += 1 if "=" in word else 2
            if flag in INLINE and nesting < MAX_NESTING:
                found += executed(value, nesting + 1)
            elif flag in LOADS:
                found.append((value, False))
            continue
        if not word.startswith("-") and word != "run":
            found.append((word, primary))
            primary = False
        index += 1
    return found


@lru_cache(maxsize=256)
def runs(folder: str, body: str, *, primary_only: bool = False) -> frozenset[str]:
    """Every repository path the body may run from `folder`, each name expanded the way node and shells resolve
    it (extension, index file); computed once per body, so matching a written file is one set lookup."""
    found = set()
    for candidate, primary in executed(body):
        if primary or not primary_only:
            base = posixpath.normpath(posixpath.join(folder or ".", candidate.replace("\\", "/")))
            found.update(posixpath.normpath(base + ext) for ext in EXTENSIONS)
    return frozenset(found)
