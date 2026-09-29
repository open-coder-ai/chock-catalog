# Rule catalogue

Generated from the rule registry; a test fails when this file and the registry differ. Each rule
lists its pack, default verdict, weakness (CWE), OWASP Top 10 for Agentic Applications entry (ASI)
and the fix its refusal names. A selection (`.chock/agentic-security.json`) sets a verdict per
pack or per rule; a waiver is `# chock: allow <rule-id>` or `// chock: allow <rule-id>`, a human's
decision, and JSON is waived in the selection file only.

## exec: Agent code execution (ASI05)

AutoGen, CrewAI and LangChain settings and tools that run model-written code or requests on the host.

### exec-autogen-local-execution
- pack: exec; default: deny; reads: python; CWE: CWE-94; ASI: ASI05
- what: "use_docker": False in a code_execution_config; LocalCommandLineCodeExecutor(...)
- why: Code the model writes runs as the operator's user with the operator's files and credentials; Docker is the boundary AutoGen's own documentation asks for.
- fix: run the executor in Docker (DockerCommandLineCodeExecutor, or code_execution_config {"use_docker": True}).
- silent on: DockerCommandLineCodeExecutor, use_docker True, code_execution_config False
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://microsoft.github.io/autogen/0.2/docs/tutorial/code-executors/

### exec-crewai-unsafe-mode
- pack: exec; default: deny; reads: python; CWE: CWE-94; ASI: ASI05
- what: allow_code_execution=True together with code_execution_mode="unsafe"
- why: Unsafe mode runs generated code directly on the host, with no container between a prompt injection and the shell.
- fix: drop code_execution_mode="unsafe" (the default "safe" mode runs in Docker) or remove allow_code_execution.
- silent on: allow_code_execution=True in the default mode, code_execution_mode="safe"
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://docs.crewai.com/concepts/agents

### exec-langchain-dangerous-code
- pack: exec; default: deny; reads: python; CWE: CWE-94, CWE-95; ASI: ASI05
- what: allow_dangerous_code=True; PythonREPLTool(...); PythonAstREPLTool(...); LLMMathChain
- why: These tools evaluate model output in the host process, so a prompt injection becomes code execution (CVE-2023-29374).
- fix: run code in a sandbox service (a container or microVM) behind a fixed-shape tool; drop the REPL tool and the flag.
- silent on: a sandboxed executor tool, a calculator tool with a fixed grammar
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://nvd.nist.gov/vuln/detail/CVE-2023-29374

### exec-langchain-dangerous-requests
- pack: exec; default: deny; reads: python; CWE: CWE-918; ASI: ASI05
- what: allow_dangerous_requests=True
- why: The flag lets the model choose any URL, so an injected prompt can reach internal services and cloud metadata endpoints (SSRF).
- fix: drop allow_dangerous_requests and give the tool a fixed set of allowed hosts behind an egress allowlist.
- silent on: a request tool whose hosts are fixed in code
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://python.langchain.com/docs/security/

## supply: Agentic supply chain (ASI04)

MCP server launch commands and URLs, remote model code, model hub downloads and prompt hub pulls.

### supply-mcp-unpinned-package
- pack: supply; default: deny; reads: json, toml; CWE: CWE-829; ASI: ASI04
- what: an MCP server whose command is npx, uvx, bunx or pipx run with a package argument lacking an exact version
- why: An unpinned launcher fetches whatever the registry serves today and runs it with the user's privileges; a hijacked release runs on the next start.
- fix: pin the package to an exact version: npx -y pkg@1.2.3, uvx pkg==1.2.3 (name@latest stays with block-unpinned-agent-components).
- silent on: npx -y pkg@1.2.3, uvx pkg==1.2.3, a local script path, a docker or python command
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

### supply-uvx-git-unpinned
- pack: supply; default: deny; reads: json, toml, python, js, yaml, shell; CWE: CWE-829, CWE-494; ASI: ASI04
- what: uvx --from git+... (or an MCP server doing so) with no @<40-hex sha> on the spec
- why: A branch or tag in a git URL moves; only a commit SHA names one reviewed tree.
- fix: append the full 40-hex commit: uvx --from git+https://host/org/repo@<sha> tool.
- silent on: git+https://host/org/repo@<40-hex sha>, a tag-only reference is refused too
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://docs.astral.sh/uv/guides/tools/

### supply-mcp-remote-http
- pack: supply; default: deny; reads: json, toml, python, yaml; CWE: CWE-319; ASI: ASI04
- what: an MCP server "url" starting http:// whose host is not localhost, 127.x or ::1
- why: Plain HTTP lets anyone on the path read tool calls and results, or answer as the server.
- fix: use https:// for a remote MCP server; plain http is for localhost only.
- silent on: https:// URLs, http://localhost and http://127.0.0.1
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

### supply-trust-remote-code
- pack: supply; default: deny; reads: python; CWE: CWE-829, CWE-94; ASI: ASI04
- what: trust_remote_code=True in a call or config dict
- why: The flag executes Python from the model repository at load time, so a change in that repository is code execution on your host.
- fix: load with trust_remote_code=False and a natively supported architecture, or vendor and review the code at a pinned revision.
- silent on: trust_remote_code=False or absent
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://huggingface.co/docs/transformers/en/models#trust-remote-code

### supply-hf-unpinned-revision
- pack: supply; default: allow; reads: python; CWE: CWE-494; ASI: ASI04
- what: from_pretrained(...) or hf_hub_download(...) with no revision= (a local path is exempt)
- why: A hub name follows the default branch, so the weights or code you tested can change under you.
- fix: pass revision=<commit sha> so the artifact cannot change under you.
- silent on: calls passing revision=, from_pretrained on a local directory
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://huggingface.co/docs/huggingface_hub/en/guides/download

### supply-langchain-hub-unpinned
- pack: supply; default: deny; reads: python; CWE: CWE-494; ASI: ASI04
- what: hub.pull("owner/name") with no :<commit> suffix
- why: A prompt pulled by name can be edited by its owner at any time and becomes your agent's instructions.
- fix: pin the commit: hub.pull("owner/name:<commit hash>").
- silent on: hub.pull("owner/name:<commit hash>")
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://docs.smith.langchain.com/prompt_engineering/how_to_guides/manage_prompts_programatically

## tools: Agent tool misuse (ASI02)

Python functions registered as agent tools that pass their string parameters to a subprocess, and shell tools.

### tools-shell-injection-via-tool-param
- pack: tools; default: deny; reads: python; CWE: CWE-78; ASI: ASI02
- what: @tool, @function_tool, @mcp.tool, server.tool(...) or Tool(func=...) functions whose str parameter reaches subprocess.*, os.system or os.popen
- why: The model writes tool arguments and prompt injection steers what it writes; a string that reaches a subprocess is a command the attacker chose.
- fix: map the parameter to a fixed command through a table (COMMANDS[action]) or check it against an allowlist first; never build argv from the model's string.
- silent on: a fixed argv, a table lookup keyed by the parameter, an allowlist membership check, shlex.quote
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://cwe.mitre.org/data/definitions/78.html

### tools-shell-tool-instantiation
- pack: tools; default: deny; reads: python, js; CWE: CWE-78; ASI: ASI02
- what: ShellTool(...), TerminalTool(...), BashTool(...) instantiated
- why: A generic shell tool gives the model every command its user can run, with no per-action check.
- fix: expose the specific operations the task needs as typed tools instead of a shell.
- silent on: typed single-purpose tools
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://python.langchain.com/docs/security/

## approval: Human approval (ASI02, ASI09)

Hosted-tool, AutoGen, Claude Agent SDK and MCP client settings that remove the human's approval step.

### approval-hosted-mcp-never
- pack: approval; default: deny; reads: python, js; CWE: CWE-862; ASI: ASI02, ASI09
- what: require_approval="never" (requireApproval: "never" in TypeScript) on a hosted MCP tool
- why: The approval step is the one human check between a tool call and its effect; never removes it for every tool the server exposes.
- fix: use require_approval="always", or a per-tool map that names only read-only tools under "never".
- silent on: require_approval="always", a per-tool {"never": {"tool_names": [...]}} map, an approval callback
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations

### approval-autogen-no-human-input
- pack: approval; default: deny; reads: python; CWE: CWE-862; ASI: ASI09, ASI02
- what: human_input_mode="NEVER" in a call that also sets code_execution_config or code_executor
- why: An agent that executes code and never asks a human has nobody to stop a bad step.
- fix: set human_input_mode="ALWAYS" (or "TERMINATE") on the agent that executes code, or remove its code_execution_config.
- silent on: human_input_mode="NEVER" with code_execution_config False, "ALWAYS" or "TERMINATE"
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://microsoft.github.io/autogen/0.2/docs/tutorial/human-in-the-loop/

### approval-claude-sdk-bypass-permissions
- pack: approval; default: deny; reads: python, js; CWE: CWE-862; ASI: ASI02, ASI09
- what: permission_mode="bypassPermissions" (permissionMode in TypeScript) outside test files
- why: bypassPermissions runs every tool, Bash and file writes included, without a prompt.
- fix: use permission_mode "default" or "acceptEdits" with an allowed_tools list, and a can_use_tool callback for the rest.
- silent on: the same setting in a test file, any other permission mode
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://docs.claude.com/en/api/agent-sdk/permissions

### approval-mcp-autoapprove-write-tools
- pack: approval; default: deny; reads: json, toml; CWE: CWE-862; ASI: ASI02, ASI09
- what: an autoApprove or alwaysAllow list holding a tool named write|delete|exec|run|shell|deploy|push|send*
- why: Auto-approving a state-changing tool means the client never asks before it writes, deletes, runs or sends.
- fix: keep write, delete, exec, run, shell, deploy, push and send tools out of autoApprove and alwaysAllow so each call asks.
- silent on: autoApprove lists of read-only tools (read_file, list_directory, search)
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations

## identity: Identity and privilege (ASI03)

The whole host environment passed to a subprocess or sandbox, and credential stores mounted into agent containers.

### identity-env-passthrough
- pack: identity; default: deny; reads: python, js; CWE: CWE-200; ASI: ASI03
- what: env=os.environ, env=dict(os.environ), env={**os.environ}, os.environ.copy(); env: process.env in JS
- why: The child sees every token, key and password in the parent's environment, so whatever the model steers can read and send them.
- fix: build the child's environment from an explicit allowlist ({'PATH': ..., 'LANG': ...}) holding only what it needs.
- silent on: an explicit dict of named variables, a single process.env.NAME
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### identity-sensitive-mount
- pack: identity; default: deny; reads: yaml, python, js, shell; CWE: CWE-522, CWE-250; ASI: ASI03
- what: a volume or bind mount of ~/.aws, ~/.config/gcloud, ~/.ssh or /var/run/docker.sock in a file about an agent or sandbox
- why: A mounted credential store or the Docker socket gives code in the container the operator's cloud identity, or root on the host.
- fix: mount a scoped, read-only working directory only; give the container short-lived credentials, never the operator's ~/.aws, ~/.ssh, gcloud config or the Docker socket.
- silent on: a mount of a project directory, a container-side path named .aws, files with no agent or sandbox in them
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## comms: Inter-agent communication (ASI07)

TLS certificate verification disabled in Python HTTP clients, the ssl module and Node.

### comms-tls-verify-disabled
- pack: comms; default: deny; reads: python; CWE: CWE-295; ASI: ASI07
- what: verify=False on a requests, httpx, urllib3 or aiohttp call, client or session (also session.verify = False)
- why: Without verification anyone on the network path can impersonate the peer and read or alter agent traffic.
- fix: remove verify=False; if a private CA signs the peer, pass verify='/path/to/ca.pem'.
- silent on: verify=True, verify='/path/to/ca.pem', no verify argument
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification

### comms-ssl-context-unverified
- pack: comms; default: deny; reads: python; CWE: CWE-295, CWE-297; ASI: ASI07
- what: ssl._create_unverified_context, ssl.CERT_NONE, check_hostname = False
- why: A context that accepts any certificate authenticates nobody, so the encryption protects nothing from a man in the middle.
- fix: use ssl.create_default_context() and leave check_hostname and verify_mode at their defaults.
- silent on: ssl.create_default_context(), CERT_REQUIRED
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://docs.python.org/3/library/ssl.html#security-considerations

### comms-node-tls-disabled
- pack: comms; default: deny; reads: python, js, yaml, shell, env, dockerfile; CWE: CWE-295; ASI: ASI07
- what: rejectUnauthorized: false; NODE_TLS_REJECT_UNAUTHORIZED set to 0 in code, env files, YAML, shell or Dockerfiles
- why: One flag disables certificate checks for every HTTPS request the process makes.
- fix: remove the override; trust a private CA with NODE_EXTRA_CA_CERTS=/path/to/ca.pem instead.
- silent on: rejectUnauthorized: true, NODE_EXTRA_CA_CERTS, NODE_TLS_REJECT_UNAUTHORIZED=1
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue

## bounds: Cascading failure bounds (ASI08)

Turn, reply, recursion and iteration limits on agent loops.

### bounds-unbounded-turns
- pack: bounds; default: allow; reads: python; CWE: CWE-835, CWE-770; ASI: ASI08
- what: max_turns=None or max_consecutive_auto_reply=None
- why: With no cap a confused or manipulated agent loops on paid model calls and tools until something else stops it.
- fix: set a finite max_turns or max_consecutive_auto_reply sized to the task, and a wall-clock timeout.
- silent on: a finite limit
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://microsoft.github.io/autogen/0.2/docs/tutorial/conversation-patterns/

### bounds-recursion-limit-high
- pack: bounds; default: allow; reads: python, js; CWE: CWE-674, CWE-770; ASI: ASI08
- what: recursion_limit (recursionLimit) set to an integer of 1000 or more
- why: A limit in the thousands is no limit for a graph stuck in a cycle: cost and side effects pile up first.
- fix: keep recursion_limit at the framework default or the smallest number the graph needs, and add a stop condition.
- silent on: recursion_limit below 1000
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://langchain-ai.github.io/langgraph/concepts/low_level/#recursion-limit

### bounds-crewai-max-iter-high
- pack: bounds; default: allow; reads: python; CWE: CWE-770; ASI: ASI08
- what: max_iter set to an integer of 100 or more
- why: Hundreds of iterations per task multiply cost and repeat side effects when the agent cannot finish.
- fix: keep max_iter near the default of 20 and let the agent report failure instead of iterating.
- silent on: max_iter below 100
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://docs.crewai.com/concepts/agents

## prompt-memory: Prompt and memory hygiene (ASI01, ASI06)

System messages assembled from retrieved or user text, and mem0 calls with no user, agent or run scope.

### prompt-untrusted-in-system-message
- pack: prompt-memory; default: allow; reads: python; CWE: CWE-1427; ASI: ASI01
- what: a system message built with an f-string, .format(), % or + from variables named doc, chunk, context, retrieved, email, page, html, tool_output or user_input
- why: The system channel is read as instructions; retrieved or user text placed there is prompt injection with the highest authority.
- fix: keep the system message constant; pass retrieved text as a user or tool message, delimited and labelled as data.
- silent on: a constant system message, the same variables in a user message
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://genai.owasp.org/llmrisk/llm01-prompt-injection/

### memory-mem0-unscoped
- pack: prompt-memory; default: allow; reads: python; CWE: CWE-639; ASI: ASI06
- what: a mem0 client's .add( or .search( with none of user_id, agent_id, run_id (or a filters dict naming one)
- why: Memory with no owner pools every user's facts, so one user's session can read or poison another's.
- fix: pass user_id, agent_id or run_id on every add() and search() so one user's memory is never another's context.
- silent on: calls passing a scope, add/search on other objects
- refs: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ https://docs.mem0.ai/core-concepts/memory-operations/add

## code: Code safety

Python eval and exec of non-literal text, and SQL assembled from strings in Python and JavaScript.

### code-dynamic-eval-exec
- pack: code; default: deny; reads: python; CWE: CWE-95; ASI: none
- what: eval(x) or exec(x) where x is not a string literal (bare eval( is also block-unsafe-code-execution's)
- why: eval and exec of a variable run whatever the text says, and in agent code that text often comes from a model.
- fix: parse with ast.literal_eval or json.loads, or dispatch through a table of named functions.
- silent on: ast.literal_eval, model.eval(), eval of a string literal
- refs: https://docs.python.org/3/library/functions.html#eval https://cwe.mitre.org/data/definitions/95.html

### code-sql-string-built
- pack: code; default: deny; reads: python, js; CWE: CWE-89; ASI: none
- what: .execute(, .executemany(, .query(, .raw( whose statement is an f-string, %-format, .format() or + concatenation; JS query( or execute( over a template literal with ${}
- why: Values spliced into SQL become syntax, and model output is untrusted input.
- fix: bind values as parameters: cursor.execute('... WHERE id = %s', (value,)); in JS pass a values array.
- silent on: parameterised queries, constant SQL, session.query(Model), .query( on a non-SQL string
- refs: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## provenance: Content provenance

C2PA, Content Credentials, SynthID and AI-generated markers a file carried at HEAD.

### provenance-marker-removed
- pack: provenance; default: deny; reads: python, js, json, yaml, toml, shell, dockerfile, env, other; CWE: none; ASI: none
- what: a written file whose HEAD version held c2pa, content_credentials, synthid, ai_generated, x-ai-generated, digitalSourceType or trainedAlgorithmicMedia and whose new version holds none, when no other written file carries the marker
- why: Article 50 of the EU AI Act requires machine-readable marking of AI-generated content; stripping the marker removes it without anyone deciding to.
- fix: keep the marker, or move it to the file that now does the marking in the same change; only a person waives this, in the selection file.
- silent on: a file that keeps one marker, a marker moved to another file in the same change, a new file
- refs: https://eur-lex.europa.eu/eli/reg/2024/1689/oj https://c2pa.org/specifications/specifications/2.1/index.html
