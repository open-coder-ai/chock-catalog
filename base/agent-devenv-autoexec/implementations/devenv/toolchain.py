"""Shell and toolchain files that run on directory entry, at load time or on boot of a cloud IDE."""

from __future__ import annotations

import html
import re

from devenv.commands import dangerous_env, run
from devenv.core import ASK, BLOCK, Collector, dotted, key_of, network, norm, risky, strings, walk
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


_TEMPLATE_EXEC = re.compile(r"\{\{[^}]*\bexec\s*\(")


def mise(c: Collector) -> None:
    """mise runs tasks, hooks and `{{exec(...)}}` templates, sources env files and builds tools from paths or refs."""
    for path, leaf in walk(toml_value(c.text)):
        head = path[0] if path else ""
        key = key_of(path)
        spot = dotted(path)
        text = leaf if isinstance(leaf, str) else ""
        line = c.line_of(key)
        if _TEMPLATE_EXEC.search(text):
            run(c, RULE, spot, text, "mise template that runs a command when the file loads", line=line)
        elif head in ("tasks", "hooks") and text and key not in ("description", "alias", "dir"):
            run(c, RULE, spot, text, f"mise {head[:-1]} command", severity=ASK)
        elif head == "env" and path[1:2] == ("_",):
            c.add(
                RULE,
                f"{spot}={norm(leaf)}",
                f"mise env directive at {spot} sources or loads a file",
                severity=ASK,
                line=line,
            )
        elif head == "env" and len(path) == len(("env", key)) and dangerous_env(key):
            c.add(RULE, f"{spot}={norm(leaf)}", f"mise environment override {key}", line=line)
        elif head == "tools" and _VERSION_PATH.search(text):
            c.add(
                RULE,
                f"{spot}={norm(leaf)}",
                "mise tool built from a local path or a source ref",
                severity=ASK,
                line=line,
            )
        elif head == "plugins":
            c.add(RULE, f"{spot}={norm(leaf)}", "mise plugin installed from a URL", severity=ASK, line=line)
        elif head == "settings" and key in ("trusted_config_paths", "task_run_auto_install", "experimental"):
            c.add(RULE, f"{spot}={norm(leaf)}", f"mise setting {spot} widens what runs", severity=ASK, line=line)


_PARSE_SHELL = re.compile(r"\$[({]shell\s+([^)}]*)")
#: GNU make `VAR != command` runs the command when the makefile is read, as $(shell) does.
_SHELL_ASSIGN = re.compile(r"^\s*(?:override\s+|export\s+)?[^\s=:!?+]+\s*!=\s*(.*)$")


def makefile(c: Collector) -> None:
    """`$(shell ...)` outside a recipe runs on every make invocation, even `make -n`; one that reaches the network blocks."""
    for number, line in enumerate(c.lines, 1):
        if line.startswith("\t") or _comment(line):
            continue
        assigned = _SHELL_ASSIGN.match(line)
        for command in [m.group(1) for m in _PARSE_SHELL.finditer(line)] + ([assigned.group(1)] if assigned else []):
            if network(command) or risky(command):
                run(
                    c,
                    RULE,
                    f"shell@{norm(command)}",
                    command,
                    "parse-time $(shell) that reaches the network",
                    line=number,
                )


_BACKTICK = re.compile(r"`([^`\n]+)`|\bshell\(\s*(?:'([^'\n]*)'|\"([^\"\n]*)\")")


def justfile(c: Collector) -> None:
    """Backticks and shell() in a justfile assignment run when the file loads, whichever recipe is asked for."""
    for number, line in enumerate(c.lines, 1):
        if line[:1] in (" ", "\t") or _comment(line) or ":=" not in line:
            continue
        for found in _BACKTICK.finditer(line.split(":=", 1)[1]):
            command = next(group for group in found.groups() if group is not None)
            severity = BLOCK if network(command) else ASK
            label = "justfile command run at load"
            run(c, RULE, f"backtick@{norm(command)}", command, label, severity=severity, line=number)


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
        if key_of(path) in ("init", "before", "command", "prebuild"):
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
        if key_of(path) in ("run", "onBoot", "build"):
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
