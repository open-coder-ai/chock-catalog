"""What a launch line starts: an inline-code shell, or a package or image, and whether that source is pinned exactly."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh", "cmd", "powershell", "pwsh"})
#: Interpreters that run the code given on their command line, with the flags that do it.
INLINE = {
    "python": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "bun": {"-e", "--eval", "-p", "--print"},
    "deno": {"eval"}, "perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"},
}  # fmt: skip
WRAPPERS = frozenset({"env", "sudo", "doas", "nohup", "exec", "command", "timeout", "nice", "time", "xargs", "stdbuf"})
WRAPPER_VALUE_FLAGS = frozenset({"-u", "-C", "--unset", "--chdir", "-n", "-s", "-k", "-o", "-e"})
RUNNERS = (
    ("npm", {"npx", "bunx", "pnpx"}, ()),
    ("npm", {"pnpm", "yarn"}, ("dlx",)),
    ("npm", {"bun"}, ("x",)),
    ("npm", {"npm"}, ("exec",)),
    ("npm", {"npm"}, ("x",)),
    ("pypi", {"uvx"}, ()),
    ("pypi", {"uv"}, ("tool", "run")),
    ("pypi", {"pipx"}, ("run",)),
    ("docker", {"docker", "podman"}, ("run",)),
)
SHORT_ABBREVIATION = 2
NPM_VALUE_FLAGS = frozenset(
    {"--registry", "--cache", "--userconfig", "--prefix", "--node-options", "-w", "--workspace", "--loglevel"}
)
PY_VALUE_FLAGS = frozenset(
    [
        "--from",
        "--spec",
        "--with",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--index",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--default-index",
        "--find-links",
        "-f",
        "--constraints",
        "-c",
        "--overrides",
        "--env-file",
        "--directory",
        "--project",
        "--config-file",
        "--pip-args",
        "--suffix",
        "--refresh-package",
        "--reinstall-package",
        "--upgrade-package",
        "-P",
        "--exclude-newer",
        "--resolution",
        "--prerelease",
        "--link-mode",
        "--index-strategy",
        "--keyring-provider",
        "--cache-dir",
        "--python-preference",
    ]
)
DOCKER_VALUE_FLAGS = frozenset(
    [
        "-e",
        "--env",
        "-v",
        "--volume",
        "-p",
        "--publish",
        "--name",
        "--network",
        "--net",
        "-w",
        "--workdir",
        "-u",
        "--user",
        "--entrypoint",
        "--mount",
        "--platform",
        "--pull",
        "-l",
        "--label",
        "--env-file",
        "--add-host",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
        "-m",
        "--memory",
        "--cpus",
        "-h",
        "--hostname",
        "--device",
        "--tmpfs",
        "--ulimit",
        "--restart",
        "--runtime",
        "--gpus",
        "--log-driver",
        "--pid",
        "--ipc",
        "--uts",
        "--userns",
        "--cidfile",
        "--shm-size",
        "--stop-signal",
        "--group-add",
        "--dns",
    ]
)
EXACT_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
EXACT_PEP440 = re.compile(r"\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?")
COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
VCS_PREFIXES = ("git+", "github:", "gitlab:", "bitbucket:", "gist:", "file:", "git@")
SHORTHAND = re.compile(r"[\w.-]+/[\w.-]+(?:#.*)?")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")
PS_ABBREVIATIONS = ("-command", "-encodedcommand")


@dataclass
class Launch:
    """`name` is the program after wrappers (lowercase, no extension); `issues` are (rule, message) pairs;
    `package` is (ecosystem, package, exact version or None) for a package launcher."""

    name: str
    issues: list[tuple[str, str]] = field(default_factory=list)
    package: tuple[str, str, str | None] | None = None


def program(command: str) -> str:
    """The lowercase program name of a command: no directory, no .exe/.cmd/.bat/.ps1, no interpreter version."""
    name = re.sub(r"\.(?:exe|cmd|bat|ps1|com)$", "", command.replace("\\", "/").rsplit("/", 1)[-1].lower())
    return re.sub(r"[\d.]+$", "", name) if re.fullmatch(r"(?:python|ruby|perl|php)[\d.]*", name) else name


def unwrap(command: str, args: list[str]) -> tuple[str, list[str]]:
    """The command a wrapper (env, sudo, nohup, timeout, ...) finally runs, with its arguments."""
    while program(command) in WRAPPERS:
        i = 0
        while i < len(args) and (args[i].startswith("-") or "=" in args[i] or re.fullmatch(r"\d+[smhd]?", args[i])):
            i += 2 if args[i] in WRAPPER_VALUE_FLAGS else 1
        if i >= len(args):
            break
        command, args = args[i], args[i + 1 :]
    return command, args


def _runs_inline(name: str, args: list[str]) -> bool:
    """Whether a shell or interpreter is given code on its command line instead of a script."""
    if name == "python":
        return any(re.fullmatch(r"-[A-Za-z]*c", arg) for arg in args)
    if name in INLINE:
        return any(arg.partition("=")[0] in INLINE[name] for arg in args)
    low = [arg.lower() for arg in args]
    if name in {"cmd"}:
        return any(arg in {"/c", "/k", "/r"} for arg in low)
    if name in {"powershell", "pwsh"}:
        return any(
            arg in {"-c", "-e", "-ec"}
            or (len(arg) > SHORT_ABBREVIATION and any(p.startswith(arg) for p in PS_ABBREVIATIONS))
            for arg in low
        )
    return any(re.fullmatch(r"-[a-z]{0,4}c[a-z]{0,4}|--command", arg) for arg in args)


def _family(name: str, args: list[str]) -> tuple[str, list[str]] | None:
    """('npm' | 'pypi' | 'docker', the arguments after the runner's own verb) for a package or image launcher."""
    if name in {"npm", "pnpm", "yarn", "bun"}:
        args = args[next((i for i, arg in enumerate(args) if not arg.startswith("-")), len(args)) :]
    for family, names, verb in RUNNERS:
        if name in names and tuple(args[: len(verb)]) == verb:
            return family, args[len(verb) :]
    return None


def _option_values(
    args: list[str], takes_value: frozenset[str], wanted: set[str]
) -> tuple[dict[str, list[str]], list[str]]:
    """({wanted flag: its values}, the positional arguments) of an argument list up to the first positional."""
    found: dict[str, list[str]] = {flag: [] for flag in wanted}
    i = 0
    while i < len(args) and args[i].startswith("-"):
        flag, eq, value = args[i].partition("=")
        if flag in wanted:
            if eq or i + 1 < len(args):
                found[flag].append(value if eq else args[i + 1])
            i += 1 if eq else 2
        else:
            i += 2 if flag in takes_value and not eq else 1
    return found, args[i:]


def _split_npm(spec: str) -> tuple[str, str | None]:
    at = spec.rfind("@")
    return (spec, None) if at <= 0 else (spec[:at], spec[at + 1 :])


def _npm_spec(spec: str, launch: Launch, *, main: bool) -> None:
    """Pin check of one npm package spec: exact semver, or a git source fixed to a commit; local paths are left alone."""
    spec = spec.removeprefix("npm:")
    if spec.startswith((".", "/", "~")):
        return
    if "://" in spec or spec.startswith(VCS_PREFIXES) or SHORTHAND.fullmatch(spec):
        if not re.search(r"#" + COMMIT.pattern + "$", spec):
            launch.issues.append(("unpinned", "its package comes from a git or url source not fixed to a commit"))
        return
    name, version = _split_npm(spec)
    exact = version is not None and EXACT_SEMVER.fullmatch(version) is not None
    if not exact:
        launch.issues.append(("unpinned", "its package is not pinned to an exact version (name@x.y.z)"))
    if main:
        launch.package = ("npm", name.lower(), version if exact else None)


def _py_spec(spec: str, launch: Launch, *, main: bool) -> None:
    """Pin check of one Python requirement: `name==x.y.z`, `name@x.y.z`, or a git source fixed to a commit."""
    spec = re.sub(r"\[[^\]]*\]", "", spec.strip())
    if spec.startswith((".", "/", "~")):
        return
    if "://" in spec or spec.startswith(VCS_PREFIXES) or " @ " in spec:
        if not re.search(r"@" + COMMIT.pattern + r"(?:#.*)?$", spec):
            launch.issues.append(("unpinned", "its package comes from a git or url source not fixed to a commit"))
        return
    parsed = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(==|@)?(.*)", spec)
    name, sep, version = parsed.groups() if parsed else ("", None, "")
    exact = sep is not None and EXACT_PEP440.fullmatch(version) is not None
    if not exact:
        launch.issues.append(("unpinned", "its package is not pinned to an exact version (name==x.y.z)"))
    if main:
        launch.package = ("pypi", re.sub(r"[-_.]+", "-", name.lower()), version if exact else None)


def _npm(args: list[str], launch: Launch) -> None:
    found, rest = _option_values(args, NPM_VALUE_FLAGS, {"-p", "--package", "-c", "--call"})
    if found["-c"] or found["--call"]:
        launch.issues.append(("inline", "it runs a shell command line (npx -c)"))
    specs = [*found["-p"], *found["--package"]] or rest[:1]
    for spec in specs:
        _npm_spec(spec, launch, main=len(specs) == 1)


def _py(args: list[str], launch: Launch) -> None:
    found, rest = _option_values(args, PY_VALUE_FLAGS, {"--from", "--spec", "--with"})
    main = [*found["--from"], *found["--spec"]] or rest[:1]
    for spec in main:
        _py_spec(spec, launch, main=len(main) == 1)
    for spec in found["--with"]:
        _py_spec(spec, launch, main=False)


def _docker(args: list[str], launch: Launch) -> None:
    _, rest = _option_values(args, DOCKER_VALUE_FLAGS, set())
    if rest and not DIGEST.search(rest[0]):
        launch.issues.append(("unpinned", "its image is not pinned by digest (image@sha256:...)"))


def analyze(command: str, args: list[str]) -> Launch:
    """The launcher a command and arguments start, after wrappers, with every pin or shell issue found."""
    command, args = unwrap(command, args)
    launch = Launch(program(command))
    if launch.name in SHELLS | INLINE.keys() and _runs_inline(launch.name, args):
        launch.issues.append(("inline", "it runs a shell or interpreter command line instead of a pinned package"))
    family = _family(launch.name, args)
    if family:
        {"npm": _npm, "pypi": _py, "docker": _docker}[family[0]](family[1], launch)
    return launch
