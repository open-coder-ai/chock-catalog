"""block-unsafe-code-execution v2: each rule refuses its sink, spares its look-alikes, and nothing v1 refused passes."""

from __future__ import annotations

import re

import pytest
import yaml
from policies import gatekit

POLICY = "block-unsafe-code-execution"
PATTERN = re.compile(gatekit.gate_spec(POLICY)["params"]["content_pattern"])
# The 0.0.4 pattern, kept verbatim: v2 may only add refusals.
V1 = re.compile(
    r"(?<![\w.])(eval|exec)\s*\(|shell\s*=\s*True|os\.(system|popen)\s*\(|subprocess\.getoutput\s*\("
    r"|pickle\.loads?\s*\(|marshal\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|execSync\s*\(|new\s+Function\s*\("
)

REFUSED = {
    "child-process-exec CWE-78": [
        "child_process.exec(cmd, cb)",
        "cp.exec(`git log ${ref}`)",
        "childProcess . exec(cmd)",
        "require('child_process').exec(userCmd)",
        "require('node:child_process').exec(userCmd)",
    ],
    "implicit-shell CWE-78": [
        "status, out = subprocess.getstatusoutput(cmd)",
        "commands.getoutput(cmd)",
        "os.execvp(prog, args)",
        "os.execve(path, args, env)",
        "os.spawnlp(os.P_WAIT, prog, prog)",
        "os.posix_spawn(path, argv, env)",
        "await asyncio.create_subprocess_shell(cmd)",
    ],
    "runtime-exec CWE-78": ["Process p = Runtime.getRuntime().exec(cmd);", "rt.getRuntime() .exec(cmd)"],
    "shell-mode CWE-78": [
        "subprocess.run(cmd, shell=1)",
        "spawn(cmd, { shell: true })",
        'spawn(cmd, {"shell": true})',
        'subprocess.run(cmd, **{"shell": True})',
    ],
    "shell-eval-expansion CWE-78": [
        'eval "$cmd"',
        "eval $cmd",
        'eval "export $name=$value"',
        'eval "${args[@]}"',
        "eval $@",
    ],
    "eval-exec-receiver CWE-95": [
        "window.eval(src)",
        "globalThis.eval(src)",
        "builtins.exec(src)",
        "__builtins__.eval(s)",
    ],
    "eval-exec-indirect CWE-95": [
        "getattr(builtins, 'eval')(src)",
        "(0, eval)(src)",
        "window['eval'](src)",
        'cp["execSync"](cmd)',
        "const e = eval;",
        "eval?.(src)",
    ],
    "function-constructor CWE-95": ["const f = Function(body);", "const f = Function('a', body);", "Function()"],
    "string-timer CWE-95": [
        "setTimeout('tick()', 100)",
        'setInterval("poll()", 5)',
        "window.setTimeout(`run(${x})`, 5)",
    ],
    "compile-builtin CWE-95": [
        "code = compile(src, '<gen>', 'exec')",
        "c = compile(open(p).read(), p, 'exec')",
        'compile(e, "", "eval")',
    ],
    "vm-run CWE-95": [
        "vm.runInNewContext(src, sandbox)",
        "vm.runInThisContext(src)",
        "new vm.Script(src)",
        "vm.compileFunction(b)",
    ],
    "dynamic-import CWE-470": [
        "mod = __import__(name)",
        "__import__('os').system(cmd)",
        "importlib.import_module(name)",
        'import_module(f"plugins.{name}")',
    ],
    "deserialize CWE-502": [
        "obj = jsonpickle.decode(blob)",
        "obj = dill.loads(blob)",
        "obj = cPickle.load(fh)",
        "db = shelve.open(path)",
        "u = pickle.Unpickler(fh)",
    ],
    "yaml-unsafe CWE-502": [
        "data = yaml.unsafe_load(fh)",
        "data = yaml.unsafe_load_all(fh)",
        "cfg = yaml.load(fh, Loader=yaml.UnsafeLoader)",
        "cfg = yaml.load(fh, Loader=MySafeLoader)",
        "docs = yaml.load_all(fh)",
        "y = YAML(typ='unsafe')",
    ],
    "model-load CWE-502": [
        "model = torch.load(path)",
        "model = torch.load(path, map_location='cpu')",
        "model = torch.load(path)  # weights_only=True",
        "arr = np.load(path, allow_pickle=True)",
    ],
    "v1 rules, unchanged": [
        "result = eval(x)",
        "subprocess.run(cmd, shell=True)",
        "os.system(cmd)",
        "pickle.loads(b)",
        "yaml.load(fh)",
        "execSync(cmd)",
        "new Function(body)",
        "cfg = yaml.load(open(p), Loader=yaml.SafeLoader)",
    ],
}

SPARED = {
    "method calls on other receivers": [
        "model.eval()",
        "m = pattern.exec(line)",
        "self.exec(query)",
        "r = self.eval(e)",
    ],
    "literal-only evaluators": ["value = ast.literal_eval(text)", "rx = re.compile(r'exec')"],
    "safe yaml": [
        "data = yaml.safe_load(fh)",
        "cfg = yaml.load(fh, Loader=yaml.SafeLoader)",
        "cfg = yaml.load(fh, Loader=yaml.CSafeLoader)",
    ],
    "definitions and literal calls": [
        "def compile(self, source, filename, mode):",
        "f = Function('f')",
        "x = Function('a', 'b', 'return a + b')",
        "class Function(Base):",
        "def Function(name):",
        "function Function(x) {",
        "isFunction(x)",
        "* @param func { Function(offset: number) => number }",
        "[Function (anonymous)]",
        r"r'Find|Function(?:End)?|'",
    ],
    "timers with callbacks": ["setTimeout(() => tick(), 100)", "setTimeout(tick, 100)", "socket.setTimeout(5000)"],
    "literal imports": [
        "importlib.import_module('json')",
        "import_module('.views', package=__name__)",
        "__import__('pkg_resources').declare_namespace(__name__)",
    ],
    "safe model loads": [
        "model = torch.load(path, weights_only=True)",
        "arr = np.load(path)",
        "arr = np.load(path, allow_pickle=False)",
        "pickle.dumps(obj)",
    ],
    "shell-init eval and argument vectors": [
        'eval "$(ssh-agent -s)"',
        'eval "$(pyenv init -)"',
        "eval `dircolors`",
        'node --eval "$code"',
        "cp.execFile('git', ['status'])",
        "child_process.execFile(bin, args)",
        "spawn(cmd, args, { shell: false })",
        "subprocess.run(['ls', '-l'])",
        "subprocess.run(cmd, shell=False)",
        "subprocess.run(cmd, shell=10)",
    ],
    "prose and look-alike names": [
        "evaluation = score(x)",
        "use the eval builtin carefully",
        "vm.$emit('x')",
        "os.path.join(a, b)",
        "shell_open(path)",
    ],
}


def _cases(table: dict[str, list[str]]) -> list:
    return [pytest.param(line, id=f"{rule}: {line}") for rule, lines in table.items() for line in lines]


@pytest.mark.parametrize("line", _cases(REFUSED))
def test_the_rule_refuses_its_sink(line: str) -> None:
    assert PATTERN.search(line)


@pytest.mark.parametrize("line", _cases(SPARED))
def test_the_look_alike_is_spared(line: str) -> None:
    assert not PATTERN.search(line)


@pytest.mark.parametrize("line", _cases(REFUSED) + _cases(SPARED))
def test_nothing_v1_refused_is_now_allowed(line: str) -> None:
    assert not V1.search(line) or PATTERN.search(line)


def test_every_cwe_the_rules_name_is_claimed() -> None:
    manifest = yaml.safe_load((gatekit.policy_dir(POLICY) / "manifest.yaml").read_text(encoding="utf-8"))
    claimed = {c["control"] for c in manifest["compliance"]["cwe"]}
    named = {rule.split()[-1] for rule in REFUSED if rule.split()[-1].startswith("CWE-")}
    assert named == claimed
