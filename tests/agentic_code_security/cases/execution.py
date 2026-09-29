"""exec and bounds packs: code execution on the host, and loops with no stop."""

from __future__ import annotations

from agentic_code_security.cases.case import Case

REFUSED = [
    Case(
        "exec-autogen-local-execution",
        "agents/proxy.py",
        'from autogen import UserProxyAgent\n\nproxy = UserProxyAgent("u", code_execution_config={"work_dir": "coding", "use_docker": False})\n',
        "runs AutoGen code with use_docker False",
    ),
    Case(
        "exec-autogen-local-execution",
        "agents/executor.py",
        "from autogen.coding import LocalCommandLineCodeExecutor\n\nexecutor = LocalCommandLineCodeExecutor(work_dir='coding')\n",
        "builds a LocalCommandLineCodeExecutor",
    ),
    Case(
        "exec-crewai-unsafe-mode",
        "crew/agents.py",
        'from crewai import Agent\n\ndev = Agent(role="dev", goal="g", backstory="b", allow_code_execution=True, code_execution_mode="unsafe")\n',
        "turns on CrewAI code execution in unsafe mode",
    ),
    Case(
        "exec-langchain-dangerous-code",
        "lc/pandas_agent.py",
        "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)\n",
        "sets allow_dangerous_code=True on a LangChain agent",
    ),
    Case(
        "exec-langchain-dangerous-code",
        "lc/tools.py",
        "tools = [PythonREPLTool(), PythonAstREPLTool(locals={})]\n",
        "hands the agent a Python REPL tool",
    ),
    Case(
        "exec-langchain-dangerous-code",
        "lc/math.py",
        "chain = LLMMathChain.from_llm(llm)\n",
        "builds an LLMMathChain",
    ),
    Case(
        "exec-langchain-dangerous-requests",
        "lc/requests_toolkit.py",
        "toolkit = RequestsToolkit(requests_wrapper=wrapper, allow_dangerous_requests=True)\n",
        "sets allow_dangerous_requests=True",
    ),
    Case(
        "bounds-unbounded-turns",
        "loop/turns.py",
        "result = agent.run(task, max_turns=None)\n",
        "sets max_turns=None",
    ),
    Case(
        "bounds-unbounded-turns",
        "loop/replies.py",
        'assistant = AssistantAgent("a", max_consecutive_auto_reply=None)\n',
        "sets max_consecutive_auto_reply=None",
    ),
    Case(
        "bounds-recursion-limit-high",
        "graph/run.py",
        'out = graph.invoke(state, config={"recursion_limit": 5000})\n',
        "sets a recursion_limit of 5000",
    ),
    Case(
        "bounds-recursion-limit-high",
        "graph/run.ts",
        "const out = await graph.invoke(state, { recursionLimit: 2000 });\n",
        "sets recursionLimit to 2000 in TypeScript",
    ),
    Case(
        "bounds-crewai-max-iter-high",
        "crew/limits.py",
        'worker = Agent(role="w", goal="g", backstory="b", max_iter=200)\n',
        "sets max_iter to 200",
    ),
]

SILENT = [
    Case(
        "exec-autogen-local-execution",
        "agents/proxy.py",
        "from autogen import UserProxyAgent\nfrom autogen.coding import DockerCommandLineCodeExecutor\n\n"
        'a = UserProxyAgent("u", code_execution_config={"work_dir": "coding", "use_docker": True})\n'
        'b = UserProxyAgent("v", code_execution_config=False)\n'
        'c = DockerCommandLineCodeExecutor(image="python:3.12-slim")\n',
        "runs code in Docker, or not at all",
    ),
    Case(
        "exec-crewai-unsafe-mode",
        "crew/agents.py",
        'from crewai import Agent\n\na = Agent(role="r", goal="g", backstory="b", allow_code_execution=True)\n'
        'b = Agent(role="r", goal="g", backstory="b", allow_code_execution=True, code_execution_mode="safe")\n',
        "keeps CrewAI's Docker-backed default or safe mode",
    ),
    Case(
        "exec-langchain-dangerous-code",
        "lc/pandas_agent.py",
        "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=False)\ntool = SandboxedPythonTool(endpoint)\n",
        "keeps the dangerous flag off and uses a sandbox service",
    ),
    Case(
        "exec-langchain-dangerous-requests",
        "lc/requests_toolkit.py",
        "toolkit = RequestsToolkit(requests_wrapper=wrapper, allow_dangerous_requests=False)\n",
        "keeps allow_dangerous_requests off",
    ),
    Case(
        "bounds-unbounded-turns",
        "loop/turns.py",
        'result = agent.run(task, max_turns=12)\nassistant = AssistantAgent("a", max_consecutive_auto_reply=5)\n',
        "sets finite turn and reply limits",
    ),
    Case(
        "bounds-recursion-limit-high",
        "graph/run.py",
        'out = graph.invoke(state, config={"recursion_limit": 25})\nlimit = {"recursion_limit": limit_from_env}\n',
        "keeps recursion_limit small or not a literal",
    ),
    Case(
        "bounds-recursion-limit-high",
        "graph/run.ts",
        "// recursionLimit: 5000 was too many\nconst out = await graph.invoke(state, { recursionLimit: 25 });\n",
        "keeps recursionLimit small, its old value only in a comment",
    ),
    Case(
        "bounds-crewai-max-iter-high",
        "crew/limits.py",
        'worker = Agent(role="w", goal="g", backstory="b", max_iter=20)\n',
        "keeps max_iter near the default",
    ),
]
