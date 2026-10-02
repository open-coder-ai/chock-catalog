"""VS Code: tasks that run on folder open, settings that auto-approve, drop trust or run repo programs."""

from __future__ import annotations

import re

from devenv.agents import object_of
from devenv.commands import dangerous_env, run
from devenv.core import ASK, BLOCK, Collector, digest, dotted, into_repo, norm, trim, walk

FOLDER_OPEN, AUTO, TRUST, EXEC, EXT = (
    "dev-vscode-folderopen",
    "dev-vscode-autoapprove",
    "dev-vscode-trust-off",
    "dev-exec-path-settings",
    "dev-vscode-extension-recs",
)


def _depends(task: dict) -> list[str]:
    raw = task.get("dependsOn")
    items = raw if isinstance(raw, list) else [raw]
    return [str(i.get("task") if isinstance(i, dict) else i) for i in items if i is not None]


def _runs_on_open(options: object) -> bool:
    return isinstance(options, dict) and str(options.get("runOn", "")).lower() == "folderopen"


def _opened(by_name: dict[str, dict]) -> set[str]:
    """Tasks that run on folder open, and every task they depend on, transitively."""
    todo = [n for n, t in by_name.items() if _runs_on_open(t.get("runOptions"))]
    done: set[str] = set()
    while todo:
        name = todo.pop()
        if name in done:
            continue
        done.add(name)
        todo.extend(d for d in _depends(by_name.get(name, {})) if d in by_name)
    return done


def tasks(c: Collector, config: object, where: str = "tasks") -> None:
    """Tasks that run on open (or that one depends on) block; any fetch-and-run or encoded command blocks.

    The key carries a digest of the whole task and of the file's shared settings (options, per-OS blocks),
    so a change to anything a task runs with is new. Hidden output asks.
    """
    listed = config.get("tasks") if isinstance(config, dict) else None
    items = listed if isinstance(listed, list) else []
    named = [(norm(t.get("label") or t.get("taskName") or i), t) for i, t in enumerate(items) if isinstance(t, dict)]
    by_name = dict(named)
    opened = _opened(by_name)
    shared = digest({k: v for k, v in config.items() if k not in ("tasks", "version")}) if named else ""
    for name, task in named:
        spot = f"{where}.{name}"
        text = " ".join(str(leaf) for _, leaf in walk(task) if isinstance(leaf, str))
        line = c.line_of(name)
        if name in opened:
            key = f"{spot}.runOn=folderOpen#{digest(task)}{shared}"
            run(c, FOLDER_OPEN, key, text or "<no command>", "task that runs on folder open", line=line)
        else:
            run(c, FOLDER_OPEN, f"{spot}.command", text, "task command", severity=None, line=line)
        presentation = task.get("presentation") if isinstance(task.get("presentation"), dict) else {}
        if presentation.get("reveal") == "never" or presentation.get("echo") is False:
            c.add(FOLDER_OPEN, f"{spot}.hidden", f"task {name} hides its output", severity=ASK, line=line)


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


#: Setting names whose value is a program, interpreter or SDK the editor runs: the last segment's suffix.
_EXEC_KEY = re.compile(r"(?i)(?:path|executable|command|commandline|runtime|interpreter|tsdk|javahome|binary|shell)$")
#: Path settings that name folders or data the editor reads, not a program it runs.
_DATA_KEY = re.compile(
    r"(?i)(?:root|cwd|output|out|config|cache|log|base|source|src|data|dictionary|dist|build|search|watch|"
    r"include|exclude|schema|file|workspace|storage|history|snippet|template)path$"
)
_DATA_VALUE = re.compile(r"(?i)\.(?:txt|json|jsonc|md|dic|ya?ml|csv|xml|code-snippets|css|html?|svg|png|ico|lock)$")
_TERMINAL = re.compile(r"(?i)^terminal\.integrated\.(?:profiles|automationprofile|shellargs|shell)\.")
_TERMINAL_ENV = re.compile(r"(?i)^terminal\.integrated\.env\.[a-z]+$")
_TRUST_OFF = {
    "security.workspace.trust.enabled": (False,),
    "security.workspace.trust.startupprompt": ("never",),
    "security.workspace.trust.untrustedfiles": ("open",),
    "security.workspace.trust.banner": ("never",),
    "task.allowautomatictasks": ("on", True),
}
#: Terminal auto-approve keys that match every command line.
_REGEX_ALL = re.compile(r"^/(?:\^?\.[*+]\$?|\^?\[\\s\\S\][*+]\$?|\^|\$|\(\?:\)|)/[a-z]*$|^\*$")
_APPROVAL = ("autoapprove", "autoaccept", "allowlist", "yolo", "dangerously")


def _matches_anything(pattern: str) -> bool:
    """A terminal rule that approves an arbitrary command: a catch-all `/regex/` (or one that will not compile)."""
    if _REGEX_ALL.match(pattern):
        return True
    body = re.fullmatch(r"/(.*)/[a-z]*", pattern, re.DOTALL)
    if body is None:
        return False
    try:
        return re.search(body.group(1), "zq~9 x") is not None
    except re.error:
        return True


def _truthy(leaf: object) -> bool:
    return leaf is True or (isinstance(leaf, str) and leaf.strip().lower() == "true")


def _approval(c: Collector, path: tuple, leaf: object, spot: str, line: int) -> bool:
    """Report an auto-approval setting; True only when one was reported, so every other check still sees the rest."""
    parts = [str(p).lower() for p in path]
    at = next((i for i, p in enumerate(parts) if any(word in p for word in _APPROVAL)), None)
    if at is None:
        if parts and parts[-1].endswith("permissionmode") and str(leaf) in ("bypassPermissions", "dontAsk"):
            c.add(AUTO, f"{spot}={leaf}", f"permission prompts skipped at {spot}", line=line)
            return True
        return False
    if _truthy(leaf):
        pattern = str(path[at + 1]) if at + 1 < len(path) else None
        terminal = "terminal" in ".".join(parts[: at + 1])
        broad = not terminal or pattern is None or _matches_anything(pattern)
        c.add(AUTO, f"{spot}={leaf}", f"auto-approval at {spot}", severity=BLOCK if broad else ASK, line=line)
        return True
    return False


def _exec_setting(low: str, leaf: str) -> bool:
    last = low.rsplit(".", 1)[-1]
    if ".alternatetools." in f".{low}." or _TERMINAL.match(low):
        return True
    data_value = last.endswith("path") and _DATA_VALUE.search(leaf.strip())
    return bool(_EXEC_KEY.search(last)) and not _DATA_KEY.search(last) and not data_value


def settings(c: Collector, config: object, where: str = "settings") -> None:
    """Each setting is judged by its dotted name, flat (`"a.b": 1`) or nested (`"a": {"b": 1}`) alike."""
    if not isinstance(config, dict):
        return
    for path, leaf in walk(config):
        name = dotted(path)
        low = dotted(trim(path)).lower()
        spot = f"{where}.{name}"
        line = c.line_of(str(path[-1]) if path else "")
        if _approval(c, path, leaf, spot, line):
            continue
        if low in _TRUST_OFF and (leaf in _TRUST_OFF[low] or str(leaf).lower() in _TRUST_OFF[low]):
            c.add(TRUST, f"{spot}={leaf}", f"workspace trust or automatic-task guard relaxed at {spot}", line=line)
        elif _TERMINAL_ENV.match(".".join(map(str, path[:-1]))) and dangerous_env(str(path[-1])):
            c.add(EXEC, f"{spot}={norm(leaf)}", f"terminal environment override at {spot}", line=line)
        elif isinstance(leaf, str) and _exec_setting(low, leaf):
            verdict = into_repo(leaf)
            if verdict:
                message = f"editor runs a program from the repository at {spot}"
                c.add(EXEC, f"{spot}={norm(leaf)}", message, severity=verdict, line=line)
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
