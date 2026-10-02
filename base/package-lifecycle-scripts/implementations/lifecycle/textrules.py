"""Line-read hooks: Rust build.rs, Go go:generate, Gradle exec, gemspec extensions, extconf.rb, Podfile, podspec.

Comments are judged like code: a comment marker inside a multi-line string is string text a shell
may run, so skipping comment lines would let a hidden command through.
"""

from __future__ import annotations

import re

from lifecycle import ASK, BLOCK, Hit, digest, norm
from lifecycle.signals import danger

RUST_NET = re.compile(
    r"\b(?:reqwest|ureq|attohttpc|isahc|minreq|hyper|curl|ssh2|TcpStream|UdpSocket|ToSocketAddrs)\b|\bstd::net\b"
    r"|\bCommand::new\(\s*\"(?:[\w/.-]*/)?(?:sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh|curl|wget)\"\s*\)"
)
GO_GENERATE = re.compile(r"^//go:generate[ \t]+(.*)$")
GO_RUN_REMOTE = re.compile(r"(?<![\w-])go\s+run\s+(?:-\S+\s+)*([^\s./-][^\s/]*\.[^\s/]+/\S+|\S+@\S+)")
GRADLE_REMOTE = re.compile(r"(?i)\bapply\s*\(?\s*from\s*[:=]\s*(?:uri\()?\s*[\"'](?:https?|ftp)://")
GRADLE_EXEC = re.compile(
    r"\bexec\s*\{|\bexec\s*\(|\bproviders\.exec\b|\bcommandLine\b|\btype\s*:\s*Exec\b|<Exec>|\bExec::class"
    r"|[(,]\s*Exec\s*[),]"
    r"|\bProcessBuilder\s*\(|\bRuntime\.getRuntime\(\)\.exec\b|[\"'\]]\s*\.execute\(\s*\)"
)
GEM_EXTENSIONS = re.compile(r"\.extensions\s*(?:=|<<|\+=|\.push\b|\.concat\b|\.unshift\b)|^\s*extensions\s*[:=]")
RUBY_NET = re.compile(r"\bopen-uri\b|\bNet::(?:HTTP|FTP)\b|\bURI\.open\b|\bopen\(\s*[\"'](?:https?|ftp)://|\bFaraday\b"
                      r"|\bHTTParty\b|\bRestClient\b|\bOpenURI\b")  # fmt: skip
RUBY_PROCESS = re.compile(
    r"(?<![\w.])(?:system|exec|spawn|syscall)\b\s*[(\"'\s]|`[^`\n]*`|%x[(\[{<|!]|\bIO\.popen\b|\bOpen3\b"
    r"|\bKernel\.(?:system|exec|spawn)\b|\bPTY\.spawn\b"
)
PODSPEC_PREPARE = re.compile(r"\.prepare_command\s*=")
HEREDOC = re.compile(r"<<([~-]?)(['\"]?)(\w+)\2")
QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
HEREDOC_LINES, BRACKET_LINES = 200, 60
#: A line whose code ends like this goes on: a trailing comma, backslash, operator or method dot.
CONTINUES = re.compile(r"(?:,|\\|\+|-|\*|&&|\|\||\.|=|\bdo|\|[\w, ]*\|)\s*$")


def build_rs(text: str) -> list[Hit]:
    """Any new or changed build.rs is asked about; one that reaches the network or a shell is blocked."""
    found = RUST_NET.search(text)
    level, why = (BLOCK, f"build script uses {found.group(0)}") if found else (ASK, "new or changed build script")
    line = text.count("\n", 0, found.start()) + 1 if found else 1
    return [Hit(line, "cargo-build-rs", "build.rs", digest(text), level, why)]


def go_source(text: str) -> list[Hit]:
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        match = GO_GENERATE.match(line)
        if not match:
            continue
        command = norm(match.group(1))
        if why := danger(command):
            hits.append(Hit(number, "go-generate", "go:generate", command, BLOCK, f"go:generate {why}"))
        elif GO_RUN_REMOTE.search(command):
            hits.append(Hit(number, "go-generate", "go:generate", command, ASK, "go:generate runs a remote module"))
    return hits


def gradle(text: str) -> list[Hit]:
    hits = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        if GRADLE_REMOTE.search(line):
            hits.append(
                Hit(number, "gradle-remote-apply", "apply from", norm(line), BLOCK, "applies a build script from a URL")
            )
        elif GRADLE_EXEC.search(line):
            statement = _statement(lines, number - 1, "//")
            why = danger(statement)
            hits.append(
                Hit(
                    number,
                    "gradle-exec",
                    "exec",
                    norm(statement),
                    BLOCK if why else ASK,
                    f"build runs a process that {why}" if why else "build runs a process",
                )
            )
    return hits


def _statement(lines: list[str], index: int, comment: str = "#") -> str:
    """The line plus what continues it: the bodies of the heredocs it opens, in order (what a shell
    receives), or the lines until its brackets balance (`system(` ... `)`, `exec {` ... `}`), so an
    edit inside either changes the key. Strings and `comment` comments are ignored when counting
    brackets. Bounded (HEREDOC_LINES, BRACKET_LINES), so a file of unclosed openers stays linear.
    """
    body, at = [lines[index]], index + 1
    openers = HEREDOC.findall(lines[index][: len(_code(lines[index], comment))])
    for flavour, _quote, tag in openers:
        for line in lines[at : at + HEREDOC_LINES]:
            body.append(line)
            at += 1
            # A plain `<<TAG` ends only at TAG in column 0; `<<~TAG` and `<<-TAG` allow indentation.
            if (line.strip() if flavour else line.rstrip("\r")) == tag:
                break
    if openers:
        return "\n".join(body)
    depth, line = _depth(lines[index], comment), lines[index]
    for following in lines[at : at + BRACKET_LINES]:
        if depth <= 0 and not CONTINUES.search(_code(line, comment)):
            break
        body.append(following)
        depth += _depth(following, comment)
        line = following
    return "\n".join(body)


def _code(line: str, comment: str) -> str:
    """The line with string literals blanked (same length) and anything from a `comment` marker on cut."""
    code = QUOTED.sub(lambda m: "_" * len(m.group(0)), line)
    cut = code.find(comment)
    return code if cut < 0 else code[:cut]


def _depth(line: str, comment: str) -> int:
    code = _code(line, comment)
    return sum(code.count(c) for c in "([{") - sum(code.count(c) for c in ")]}")


def _ruby_lines(text: str, rule: str, pattern: re.Pattern[str], what: str) -> list[Hit]:
    hits = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        if not pattern.search(line):
            continue
        statement = _statement(lines, number - 1)
        why = danger(statement) or ("reaches the network" if RUBY_NET.search(statement) else None)
        hits.append(Hit(number, rule, what, norm(statement), BLOCK if why else ASK, why or f"new or changed {what}"))
    return hits


def gemspec(text: str) -> list[Hit]:
    return _ruby_lines(text, "gem-extensions", GEM_EXTENSIONS, "native extension build")


def podspec(text: str) -> list[Hit]:
    return _ruby_lines(text, "pod-prepare-command", PODSPEC_PREPARE, "prepare_command")


def podfile(text: str) -> list[Hit]:
    """Podfile is Ruby that `pod install` evaluates: a process launch anywhere in it runs on install."""
    return _ruby_lines(text, "podfile-process", RUBY_PROCESS, "process launch at pod install")


def extconf(text: str) -> list[Hit]:
    """extconf.rb runs on `gem install`: network access is blocked, process launches are asked about."""
    hits = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        if RUBY_NET.search(line):
            hits.append(Hit(number, "extconf-network", "extconf", norm(line), BLOCK, "reaches the network"))
        elif RUBY_PROCESS.search(line):
            statement = _statement(lines, number - 1)
            why = danger(statement)
            hits.append(
                Hit(
                    number,
                    "extconf-process",
                    "extconf",
                    norm(statement),
                    BLOCK if why else ASK,
                    why or "starts a process at gem install",
                )
            )
    return hits
