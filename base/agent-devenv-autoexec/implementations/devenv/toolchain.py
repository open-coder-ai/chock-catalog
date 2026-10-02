"""Shell and toolchain files that run on directory entry, at load time or on boot of a cloud IDE."""

from __future__ import annotations

import html
import re

from devenv.commands import run
from devenv.core import ASK, BLOCK, Collector, dotted, network, norm, risky, strings, walk
from devenv.parse import toml_value, under, yaml_leaves

RULE = "dev-shell-toolchain"


def _comment(line: str) -> bool:
    return not line.strip() or line.lstrip().startswith("#")


def _lines(c: Collector, label: str, *, quiet: bool = False) -> None:
    """Each non-comment line asks (or, with `quiet`, only a fetch-and-run or encoded one, which blocks)."""
    for number, line in enumerate(c.lines, 1):
        if not _comment(line):
            run(c, RULE, f"line@{norm(line)}", line, label, severity=None if quiet else ASK, line=number)


def envrc(c: Collector) -> None:
    """direnv runs .envrc on `cd` once allowed, and asks again only when the file changes."""
    _lines(c, ".envrc line that runs on entering the directory")


def procfile(c: Collector) -> None:
    _lines(c, "Procfile process", quiet=True)


_VERSION_PATH = re.compile(r"(?:^|\s)(?:path:|ref:|\.{0,2}/|~)")


def versions(c: Collector) -> None:
    """.tool-versions/.nvmrc and kin: a version that is a local path or a source ref builds or runs that code."""
    for number, line in enumerate(c.lines, 1):
        if not _comment(line) and _VERSION_PATH.search(line):
            c.add(
                RULE,
                f"version={norm(line)}",
                "tool version points at a local path or a source ref",
                severity=ASK,
                line=number,
            )


def mise(c: Collector) -> None:
    config = toml_value(c.text)
    for path, leaf in walk(config):
        head = path[0] if path else ""
        spot = dotted(path)
        if (
            head in ("tasks", "hooks")
            and isinstance(leaf, str)
            and str(path[-1]) not in ("description", "alias", "dir")
        ):
            run(c, RULE, spot, leaf, f"mise {head[:-1]} command", severity=ASK)
        elif head == "env" and path[1:2] == ("_",):
            c.add(
                RULE,
                f"{spot}={norm(leaf)}",
                f"mise env directive at {spot} sources or loads a file",
                severity=ASK,
                line=c.line_of("_."),
            )
        elif head == "settings" and str(path[-1]) in ("trusted_config_paths", "task_run_auto_install", "experimental"):
            c.add(
                RULE,
                f"{spot}={norm(leaf)}",
                f"mise setting {spot} widens what runs",
                severity=ASK,
                line=c.line_of(str(path[-1])),
            )


_PARSE_SHELL = re.compile(r"\$[({]shell\s+([^)}]*)")


def makefile(c: Collector) -> None:
    """`$(shell ...)` outside a recipe runs on every make invocation, even `make -n`; one that reaches the network blocks."""
    for number, line in enumerate(c.lines, 1):
        if line.startswith("\t") or _comment(line):
            continue
        for found in _PARSE_SHELL.finditer(line):
            if network(found.group(1)) or risky(found.group(1)):
                run(
                    c,
                    RULE,
                    f"shell@{norm(found.group(1))}",
                    found.group(1),
                    "parse-time $(shell) that reaches the network",
                    line=number,
                )


_BACKTICK = re.compile(r"`([^`\n]+)`")


def justfile(c: Collector) -> None:
    """Backticks in a justfile assignment run when the file loads, whichever recipe is asked for."""
    for number, line in enumerate(c.lines, 1):
        if line[:1] in (" ", "\t") or _comment(line) or ":=" not in line:
            continue
        for found in _BACKTICK.finditer(line.split(":=", 1)[1]):
            severity = BLOCK if network(found.group(1)) else ASK
            run(
                c,
                RULE,
                f"backtick@{norm(found.group(1))}",
                found.group(1),
                "justfile backtick run at load",
                severity=severity,
                line=number,
            )


def taskfile(c: Collector) -> None:
    """Task runs `sh:` variables when it loads the file, and fetches remote includes."""
    leaves = yaml_leaves(c.text)
    for path, value, line in leaves:
        spot = dotted(path)
        if path[-1] == "sh" and "vars" in path:
            run(
                c,
                RULE,
                spot,
                value,
                "Taskfile dynamic variable run at load",
                severity=BLOCK if network(value) else ASK,
                line=line,
            )
        elif path[0] == "includes" and re.match(r"(?i)^(?:https?|git)://|^git@", value.strip()):
            c.add(RULE, f"{spot}={norm(value)}", "Taskfile includes a remote file", line=line)


_RUBY_EXEC = re.compile(
    r"(?:\bsystem\s*\(|\bexec\s*\(|%x[({\[]|`[^`]+`|IO\.popen|Open3\.|Net::HTTP|URI\.open|open-uri|Kernel\.spawn)"
)


def ruby_file(c: Collector) -> None:
    """Vagrantfile and Brewfile are Ruby run by every vagrant/brew bundle command; shelling out asks, the network blocks."""
    for number, line in enumerate(c.lines, 1):
        if _comment(line):
            continue
        online = network(line)
        if _RUBY_EXEC.search(line) or (online and re.search(r"\b(?:inline|tap|privileged)\b", line)):
            label = "Ruby that shells out or reaches the network"
            run(c, RULE, f"ruby@{norm(line)}", line, label, severity=BLOCK if online else ASK, line=number)


def gitpod(c: Collector) -> None:
    """.gitpod.yml tasks run when the workspace starts."""
    for path, value, line in under(yaml_leaves(c.text), "tasks"):
        if str(path[-1]) in ("init", "before", "command", "prebuild"):
            run(
                c,
                RULE,
                dotted(path),
                value,
                "workspace start task",
                severity=BLOCK if network(value) else ASK,
                line=line,
            )


def replit(c: Collector) -> None:
    """.replit `run` and `onBoot` run when the workspace starts."""
    for path, leaf in walk(toml_value(c.text)):
        if path and str(path[-1]) in ("run", "onBoot", "build"):
            for text in strings(leaf):
                run(c, RULE, dotted(path), text, "workspace start command", severity=BLOCK if network(text) else ASK)


_JB_OPTION = re.compile(
    r'<option\s+name="(SCRIPT_TEXT|SCRIPT_PATH|INTERPRETER_PATH|INTERPRETER_OPTIONS|PROGRAM_PARAMETERS)"\s+value="([^"]*)"'
)


def jetbrains(c: Collector) -> None:
    """Run configurations: an inline script or interpreter is code the IDE runs; a before-launch task asks."""
    for number, line in enumerate(c.lines, 1):
        for key, value in _JB_OPTION.findall(line):
            text = html.unescape(value)
            if text.strip():
                run(
                    c,
                    "dev-exec-path-settings",
                    f"run-config.{key}",
                    text,
                    "run configuration script",
                    severity=ASK,
                    line=number,
                )
        if "RunConfigurationTask" in line or 'name="BeforeRunTask"' in line:
            c.add(
                "dev-exec-path-settings",
                f"before-launch@{norm(line)}",
                "run configuration runs a task first",
                severity=ASK,
                line=number,
            )
