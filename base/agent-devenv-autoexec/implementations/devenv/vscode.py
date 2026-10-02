"""VS Code: tasks that run on folder open, settings that auto-approve, drop trust or run repo programs."""

from __future__ import annotations

import re

from devenv.agents import object_of
from devenv.commands import dangerous_env, run
from devenv.core import ASK, BLOCK, Collector, dotted, into_repo, norm, strings, trim, walk

FOLDER_OPEN, AUTO, TRUST, EXEC, EXT = (
    "dev-vscode-folderopen",
    "dev-vscode-autoapprove",
    "dev-vscode-trust-off",
    "dev-exec-path-settings",
    "dev-vscode-extension-recs",
)


def tasks(c: Collector, config: object, where: str = "tasks") -> None:
    """Tasks that run on open block; any task's fetch-and-run or encoded command blocks; hidden output asks."""
    listed = config.get("tasks") if isinstance(config, dict) else None
    for index, task in enumerate(listed if isinstance(listed, list) else []):
        if not isinstance(task, dict):
            continue
        name = norm(task.get("label") or task.get("taskName") or index)
        spot = f"{where}.{name}"
        command = " ".join(strings(task.get("command")) + strings(task.get("args")))
        options = task.get("runOptions") if isinstance(task.get("runOptions"), dict) else {}
        if str(options.get("runOn", "")).lower() == "folderopen":
            run(c, FOLDER_OPEN, f"{spot}.runOn=folderOpen", command or "<no command>", "task that runs on folder open")
        elif command:
            run(c, FOLDER_OPEN, f"{spot}.command", command, "task command", severity=None)
        presentation = task.get("presentation") if isinstance(task.get("presentation"), dict) else {}
        if presentation.get("reveal") == "never" or presentation.get("echo") is False:
            c.add(FOLDER_OPEN, f"{spot}.hidden", f"task {name} hides its output", severity=ASK, line=c.line_of(name))


def tasks_file(c: Collector) -> None:
    tasks(c, object_of(c.text))


def launch(c: Collector, config: object, where: str = "launch") -> None:
    listed = config.get("configurations") if isinstance(config, dict) else None
    for entry in listed if isinstance(listed, list) else []:
        if not isinstance(entry, dict):
            continue
        for key in ("preLaunchTask", "postDebugTask"):
            if isinstance(entry.get(key), str):
                spot = f"{where}.{norm(entry.get('name', ''))}.{key}"
                c.add(
                    FOLDER_OPEN, f"{spot}={norm(entry[key])}", f"{key} runs a task", severity=ASK, line=c.line_of(key)
                )


def launch_file(c: Collector) -> None:
    launch(c, object_of(c.text))


#: Setting names (last segment) whose value is a program, interpreter or SDK the editor runs.
_EXEC_KEY = re.compile(
    r"(?i)(?:^|\.)(?:path|executablepath|executable|serverpath|nodepath|pythonpath|defaultinterpreterpath|"
    r"interpreterpath|interpreter|command|overridecommand|tsdk|javahome|home|binpath|toolpath|lsppath|runtimeexecutable|"
    r"shellpath|alternatetools|serverbinary|binary)$"
)
_TERMINAL = re.compile(r"(?i)^terminal\.integrated\.(?:profiles|automationprofile|shellargs|shell)\.")
_TERMINAL_ENV = re.compile(r"(?i)^terminal\.integrated\.env\.[a-z]+$")
_TRUST_OFF = {
    "security.workspace.trust.enabled": (False,),
    "security.workspace.trust.startupprompt": ("never",),
    "security.workspace.trust.untrustedfiles": ("open",),
    "security.workspace.trust.banner": ("never",),
    "task.allowautomatictasks": ("on", True),
}
_REGEX_ALL = re.compile(r"^/(?:\^?\.[*+]\$?|\^?\[\\s\\S\][*+]\$?)/[a-z]*$|^\*$")


def settings(c: Collector, config: object, where: str = "settings") -> None:
    """Each setting is judged by its dotted name, flat (`"a.b": 1`) or nested (`"a": {"b": 1}`) alike."""
    if not isinstance(config, dict):
        return
    for path, leaf in walk(config):
        name = dotted(path)
        low = dotted(trim(path)).lower()
        spot = f"{where}.{name}"
        line = c.line_of(str(path[-1]) if path else "")
        if "autoapprove" in low or "autoaccept" in low or low.endswith("yolo"):
            if leaf is True or (isinstance(leaf, str) and leaf.lower() == "true"):
                last = str(path[-1])
                broad = _REGEX_ALL.match(last) or not low.startswith("chat.tools.terminal.autoapprove.")
                c.add(AUTO, f"{spot}={leaf}", f"auto-approval at {spot}", severity=BLOCK if broad else ASK, line=line)
        elif low in _TRUST_OFF and (leaf in _TRUST_OFF[low] or str(leaf).lower() in _TRUST_OFF[low]):
            c.add(TRUST, f"{spot}={leaf}", f"workspace trust or automatic-task guard relaxed at {spot}", line=line)
        elif _TERMINAL_ENV.match(".".join(map(str, path[:-1]))) and dangerous_env(str(path[-1])):
            c.add(EXEC, f"{spot}={norm(leaf)}", f"terminal environment override at {spot}", line=line)
        elif isinstance(leaf, str) and (_EXEC_KEY.search(low) or _TERMINAL.match(low)):
            verdict = into_repo(leaf)
            if verdict:
                c.add(
                    EXEC,
                    f"{spot}={norm(leaf)}",
                    f"editor runs a program from the repository at {spot}",
                    severity=verdict,
                    line=line,
                )
            elif _TERMINAL.match(low):
                run(c, EXEC, spot, leaf, "terminal profile argument", severity=None, line=line)


def settings_file(c: Collector) -> None:
    settings(c, object_of(c.text))


def extensions(c: Collector, config: object, where: str = "extensions") -> None:
    listed = config.get("recommendations") if isinstance(config, dict) else None
    for item in listed if isinstance(listed, list) else []:
        c.add(
            EXT,
            f"{where}={norm(item).lower()}",
            f"extension recommended: {norm(item)[:80]}",
            severity=ASK,
            line=c.line_of(str(item)),
        )


def extensions_file(c: Collector) -> None:
    extensions(c, object_of(c.text))


def workspace_file(c: Collector) -> None:
    """A *.code-workspace embeds settings, tasks, launch and extensions; each is judged as its own file is."""
    config = object_of(c.text)
    settings(c, config.get("settings"), "workspace.settings")
    tasks(c, config.get("tasks"), "workspace.tasks")
    launch(c, config.get("launch"), "workspace.launch")
    extensions(c, config.get("extensions"), "workspace.extensions")
