"""The exec pack (ASI05): agent frameworks configured to run model-written code on the host."""

from __future__ import annotations

from collections.abc import Iterator

from agentic_gate.model import FileText, Hit, Pack, Rule
from agentic_gate.pyast import callee, calls, is_const, is_false, is_true, keyword, settings, terminal

PACK = Pack(
    id="exec",
    title="Agent code execution",
    covers="AutoGen, CrewAI and LangChain settings and tools that run model-written code or requests on the host.",
    asi=("ASI05",),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_REPL_TOOLS = frozenset({"PythonREPLTool", "PythonAstREPLTool"})


def _autogen(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        if terminal(call) == "LocalCommandLineCodeExecutor":
            yield Hit(call.lineno, "LocalCommandLineCodeExecutor runs the model's code in the host shell.")
    if text.holds("code_execution", "autogen"):
        for line_no, value in settings(text, "use_docker"):
            if is_false(value):
                yield Hit(line_no, "code_execution_config with use_docker False runs the model's code on the host.")


def _crewai(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        if is_true(keyword(call, "allow_code_execution")) and is_const(keyword(call, "code_execution_mode"), "unsafe"):
            yield Hit(
                call.lineno, 'allow_code_execution=True with code_execution_mode="unsafe" skips the Docker sandbox.'
            )


def _langchain(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        if is_true(keyword(call, "allow_dangerous_code")):
            yield Hit(call.lineno, "allow_dangerous_code=True lets the agent run code it writes in this process.")
        elif terminal(call) in _REPL_TOOLS:
            yield Hit(call.lineno, f"{terminal(call)} evaluates the model's Python in this process.")
        elif "LLMMathChain" in callee(call).split("."):
            yield Hit(call.lineno, "LLMMathChain evaluates model output with numexpr/eval (CVE-2023-29374).")


def _requests(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        if is_true(keyword(call, "allow_dangerous_requests")):
            yield Hit(call.lineno, "allow_dangerous_requests=True lets the model make arbitrary network requests.")


RULES: tuple[Rule, ...] = (
    Rule(
        id="exec-autogen-local-execution",
        pack="exec",
        title="AutoGen code execution on the host",
        why="Code the model writes runs as the operator's user with the operator's files and credentials; Docker is the boundary AutoGen's own documentation asks for.",
        kinds=("python",),
        scan=_autogen,
        fix='run the executor in Docker (DockerCommandLineCodeExecutor, or code_execution_config {"use_docker": True}).',
        refuses='"use_docker": False in a code_execution_config; LocalCommandLineCodeExecutor(...)',
        silent_on="DockerCommandLineCodeExecutor, use_docker True, code_execution_config False",
        cwe=("CWE-94",),
        asi=("ASI05",),
        references=(*_OWASP, "https://microsoft.github.io/autogen/0.2/docs/tutorial/code-executors/"),
    ),
    Rule(
        id="exec-crewai-unsafe-mode",
        pack="exec",
        title="CrewAI code execution in unsafe mode",
        why="Unsafe mode runs generated code directly on the host, with no container between a prompt injection and the shell.",
        kinds=("python",),
        scan=_crewai,
        fix='drop code_execution_mode="unsafe" (the default "safe" mode runs in Docker) or remove allow_code_execution.',
        refuses='allow_code_execution=True together with code_execution_mode="unsafe"',
        silent_on='allow_code_execution=True in the default mode, code_execution_mode="safe"',
        cwe=("CWE-94",),
        asi=("ASI05",),
        references=(*_OWASP, "https://docs.crewai.com/concepts/agents"),
    ),
    Rule(
        id="exec-langchain-dangerous-code",
        pack="exec",
        title="LangChain tools that run model-written code",
        why="These tools evaluate model output in the host process, so a prompt injection becomes code execution (CVE-2023-29374).",
        kinds=("python",),
        scan=_langchain,
        fix="run code in a sandbox service (a container or microVM) behind a fixed-shape tool; drop the REPL tool and the flag.",
        refuses="allow_dangerous_code=True; PythonREPLTool(...); PythonAstREPLTool(...); LLMMathChain",
        silent_on="a sandboxed executor tool, a calculator tool with a fixed grammar",
        cwe=("CWE-94", "CWE-95"),
        asi=("ASI05",),
        references=(*_OWASP, "https://nvd.nist.gov/vuln/detail/CVE-2023-29374"),
    ),
    Rule(
        id="exec-langchain-dangerous-requests",
        pack="exec",
        title="LangChain toolkit with unrestricted network requests",
        why="The flag lets the model choose any URL, so an injected prompt can reach internal services and cloud metadata endpoints (SSRF).",
        kinds=("python",),
        scan=_requests,
        fix="drop allow_dangerous_requests and give the tool a fixed set of allowed hosts behind an egress allowlist.",
        refuses="allow_dangerous_requests=True",
        silent_on="a request tool whose hosts are fixed in code",
        cwe=("CWE-918",),
        asi=("ASI05",),
        references=(*_OWASP, "https://python.langchain.com/docs/security/"),
    ),
)
