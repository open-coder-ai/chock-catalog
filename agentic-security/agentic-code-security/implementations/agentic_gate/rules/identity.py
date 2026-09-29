"""The identity pack (ASI03): the operator's credentials handed to code the model steers."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agentic_gate import jsscan
from agentic_gate.model import FileText, Hit, Pack, Rule
from agentic_gate.pyast import calls, dotted
from agentic_gate.textscan import code_lines, find

PACK = Pack(
    id="identity",
    title="Identity and privilege",
    covers="The whole host environment passed to a subprocess or sandbox, and credential stores mounted into agent containers.",
    asi=("ASI03",),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_ENV_KEYWORDS = frozenset({"env", "envs", "environment"})
_ENVIRON = frozenset({"os.environ", "environ"})
_WRAPPERS = frozenset({"dict", "copy.copy", "copy.deepcopy"})
_JS_ENV = re.compile(r"\benv\s*:\s*(?:\{\s*\.\.\.\s*)?process\.env\b(?!\s*[.\[])")
_HOME = r"(?:~|\$\{?HOME\}?|/root|/home/[\w.-]+|/Users/[\w.-]+)"
_SENSITIVE = re.compile(
    rf"^(?:{_HOME}/\.(?:aws|ssh)|{_HOME}/\.config/gcloud|/var/run/docker\.sock|/run/docker\.sock)(?:/\S*)?$"
)
_PAIR = re.compile(r"(?:^|[\s\"'=\-\[,])([^\s:\"',\[\]=]+):/[^\s\"',\]]*")
_SOURCE = re.compile(r"\b(?:source|src)\s*[:=]\s*[\"']?([^\s\"',]+)")
_CONTEXT = ("agent", "sandbox")


def _whole_environ(value: ast.expr) -> bool:
    """os.environ itself, a copy of it, or a dict display that spreads it."""
    if isinstance(value, ast.Name | ast.Attribute):
        return dotted(value) in _ENVIRON
    if isinstance(value, ast.Call):
        name = dotted(value.func)
        return name == "os.environ.copy" or (name in _WRAPPERS and bool(value.args) and _whole_environ(value.args[0]))
    if isinstance(value, ast.Dict):
        return any(key is None and _whole_environ(item) for key, item in zip(value.keys, value.values, strict=True))
    return False


def _env_passthrough(text: FileText) -> Iterator[Hit]:
    detail = "the whole host environment (every token and key in it) goes to code the model steers."
    for call in calls(text):
        for kw in call.keywords:
            if kw.arg in _ENV_KEYWORDS and _whole_environ(kw.value):
                yield Hit(kw.value.lineno, detail)
    if text.kind == "js":
        yield from find(jsscan.shape(text.text), _JS_ENV, detail)


def _agent_context(text: FileText) -> bool:
    return text.holds(*_CONTEXT) or any(word in text.path.lower() for word in _CONTEXT)


def _mount(text: FileText) -> Iterator[Hit]:
    if not _agent_context(text):
        return
    for line_no, line in code_lines(text):
        hosts = [m.group(1) for m in _PAIR.finditer(line)] + [m.group(1) for m in _SOURCE.finditer(line)]
        if any(_SENSITIVE.match(host) for host in hosts):
            yield Hit(line_no, "a credential store or the Docker socket is mounted into an agent container.")


RULES: tuple[Rule, ...] = (
    Rule(
        id="identity-env-passthrough",
        pack="identity",
        title="Whole host environment passed to a subprocess or sandbox",
        why="The child sees every token, key and password in the parent's environment, so whatever the model steers can read and send them.",
        kinds=("python", "js"),
        scan=_env_passthrough,
        fix="build the child's environment from an explicit allowlist ({'PATH': ..., 'LANG': ...}) holding only what it needs.",
        refuses="env=os.environ, env=dict(os.environ), env={**os.environ}, os.environ.copy(); env: process.env in JS",
        silent_on="an explicit dict of named variables, a single process.env.NAME",
        cwe=("CWE-200",),
        asi=("ASI03",),
        references=(*_OWASP, "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
    ),
    Rule(
        id="identity-sensitive-mount",
        pack="identity",
        title="Credential store or Docker socket mounted into an agent container",
        why="A mounted credential store or the Docker socket gives code in the container the operator's cloud identity, or root on the host.",
        kinds=("yaml", "python", "js", "shell"),
        scan=_mount,
        fix="mount a scoped, read-only working directory only; give the container short-lived credentials, never the operator's ~/.aws, ~/.ssh, gcloud config or the Docker socket.",
        refuses="a volume or bind mount of ~/.aws, ~/.config/gcloud, ~/.ssh or /var/run/docker.sock in a file about an agent or sandbox",
        silent_on="a mount of a project directory, a container-side path named .aws, files with no agent or sandbox in them",
        cwe=("CWE-522", "CWE-250"),
        asi=("ASI03",),
        references=(*_OWASP, "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"),
    ),
)
