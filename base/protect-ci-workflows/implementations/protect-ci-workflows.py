#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse shell commands that write to CI/CD workflow config; reads and tool-driven writes pass.
# Best effort and coarse: a write must target a workflow, composite action or dependabot file (redirect, writer verb, in-place edit, git checkout/restore, cmdlets).

import os
import re
import shlex
import sys
from collections.abc import Callable

from chock_shellparse import Cmd, commands, flags_of, git_parts, operands, writes_files

PROTECTED = (".github/workflows", ".github/actions", ".github/dependabot.yml", ".github/dependabot.yaml")
REASON = "shell write touching {path} (CI/CD workflow config) is refused -- an agent must not weaken the automated checks that review its own work. Ask the person to make the change from their own shell."
NEW_BRANCH = frozenset(("-b", "-B", "--orphan"))
CODE_FLAGS = frozenset(("-c", "-e", "--eval", "-ne"))
INTERPRETERS = ("python", "perl", "ruby", "node", "php")
# Code that names a workflow and can write is refused; this lists what makes code able to write (over-matching only refuses more).
CAN_WRITE = re.compile(
    r"write|append|unlink|remove|delete|rename|replace|move|copy|rmtree|truncate|chmod|touch|symlink|mkdir|system|popen"
    r"|spawn|exec|eval|subprocess|fileutils|fileinput|inplace|in_place|sed|tee|\bdd\b|>|['\"][rbt]*[wax+][bt+]*['\"]",
    re.IGNORECASE,
)
IN_PLACE = re.compile(r"-[a-z0-9]*i[^ ]*|--in-place.*")
PATCH_HEADER = re.compile(r"^(?:diff --git |--- |\+\+\+ |rename (?:from|to) |copy (?:from|to) )(.+)$", re.MULTILINE)
PATCH_READ_CHARS = 1_000_000
VARIABLE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
SHOWN = re.compile(r"[\w.\-/\\$:]*\.github[\w.\-/\\$:]*", re.IGNORECASE)
Hit = Callable[[str], bool]


def fold(path: str) -> str:
    """The path as the filesystem reads it: slashes, no `//` or `/./`, `..` resolved, no trailing dots, spaces or stream suffix, lowercase."""
    normal = path.replace("\\", "/")
    previous = None
    while previous != normal:
        previous = normal
        normal = normal.replace("//", "/").replace("/./", "/")
    parts: list[str] = []
    for part in normal.lower().split("/"):
        if part == ".." and parts and parts[-1] not in ("", ".."):
            parts.pop()
            continue
        drive_or_dots = re.fullmatch(r"[a-z]:|\.+", part)
        parts.append(part if drive_or_dots else part.split(":", 1)[0].rstrip(". ") or part)
    return "/".join(parts)


def join(cwd: str, path: str) -> str:
    """`path` read from `cwd`, unless it is absolute or `cwd` is the repository root."""
    return path if not cwd or path.startswith(("/", "\\")) else f"{cwd}/{path}"


def hit(path: str, cwd: str = "") -> bool:
    """Whether a path, read from `cwd`, is protected, or is the `.github` folder that holds the protected ones (a dependency's own, under node_modules, is not)."""
    normal = fold(join(cwd, path))
    segments = normal.rstrip("/").split("/")
    return any(part in normal for part in PROTECTED) or (segments[-1] == ".github" and "node_modules" not in segments)


def shown(path: str) -> str:
    """The protected part of a matched argument, printable and short, for the refusal."""
    found = SHOWN.search(path)
    text = found.group() if found else path
    return "".join(char if char.isprintable() else "?" for char in text)[:120]


def expand(text: str, known: dict[str, str]) -> str:
    """`$name` and `${name}` replaced by what an earlier assignment on the line set; the rest stays."""
    return VARIABLE.sub(lambda found: known.get(found.group(1) or found.group(2), found.group()), text)


def option_values(args: list[str], short: str, long: str) -> list[str]:
    """What follows a short option (alone, ending a cluster, or glued on) or a `--long` one (`=value` or the next word)."""
    values = []
    for index, arg in enumerate(args):
        following = args[index + 1 : index + 2]
        if arg.startswith("--"):
            name, equals, value = arg.partition("=")
            if name == long:
                values += [value] if equals else following
        elif arg.startswith("-") and short in arg[1:]:
            tail = arg.split(short, 1)[1]
            values += [tail] if tail else following
    return values


def patch_names_protected(file: str, protected: Hit) -> bool:
    """Whether the patch file, if it can be read, has a header naming a protected path (a file it cannot read is not judged)."""
    try:
        with open(file, encoding="utf-8", errors="replace") as handle:
            text = handle.read(PATCH_READ_CHARS)
    except OSError:
        return False
    return any(protected(found.group(1).split("\t")[0].strip()) for found in PATCH_HEADER.finditer(text))


def applies_patch(cmd: Cmd, protected: Hit) -> bool:
    """`patch` and `git apply` write what the patch's headers name, which only the patch file shows."""
    if cmd.name == "patch":
        files = [*cmd.reads, *option_values(cmd.args, "i", "--input")]
    else:
        sub, _, rest = git_parts(cmd.args)
        reading = bool({"--check", "--stat", "--numstat", "--summary"} & set(rest)) and "--apply" not in rest
        if sub != "apply" or reading:
            return False
        files = operands(rest)
        if any(protected(arg) for arg in rest):
            return True
    return any(patch_names_protected(file, protected) for file in files)


def downloads_into(cmd: Cmd, protected: Hit) -> bool:
    """curl -o/--output and wget -O/--output-document write the file they name."""
    short, long = ("o", "--output") if cmd.name == "curl" else ("O", "--output-document")
    return any(protected(path) for path in option_values(cmd.args, short, long))


def writes_in_place(cmd: Cmd, protected: Hit) -> bool:
    """yq -i and sponge replace the file they are given."""
    if cmd.name == "yq" and not {"-i", "--inplace"} & flags_of(cmd.args):
        return False
    return any(protected(arg) for arg in operands(cmd.args))


ALSO_WRITES: dict[str, Callable[[Cmd, Hit], bool]] = {
    "curl": downloads_into,
    "wget": downloads_into,
    "yq": writes_in_place,
    "sponge": writes_in_place,
    "patch": applies_patch,
    "git": applies_patch,
}


def unbranched(cmd: Cmd) -> Cmd:
    """`git checkout -b NAME`: NAME is a new branch, not a path."""
    sub, _, rest = git_parts(cmd.args)
    if cmd.name != "git" or sub != "checkout":
        return cmd
    kept, skip = [], False
    for arg in rest:
        if skip:
            skip = False
        elif arg in NEW_BRANCH:
            skip = True
        else:
            kept.append(arg)
    return cmd._replace(args=["checkout", *kept])


def only_reads(cmd: Cmd) -> bool:
    """An interpreter given code (not an in-place flag) that shows no way to write."""
    if not cmd.name.startswith(INTERPRETERS) or not CODE_FLAGS & set(cmd.args):
        return False
    return not any(IN_PLACE.fullmatch(arg) for arg in cmd.args if arg not in CODE_FLAGS) and not CAN_WRITE.search(" ".join(cmd.args))


def written(cmd: Cmd, cwd: str) -> str | None:
    """The protected path the command writes, as written, or None."""
    found: list[str] = []

    def protected(path: str) -> bool:
        if not hit(path, cwd):
            return False
        found.append(join(cwd, path))
        return True

    cmd = unbranched(cmd)
    also = ALSO_WRITES.get(cmd.name)
    if (also and also(cmd, protected)) or writes_files(cmd._replace(args=[]) if only_reads(cmd) else cmd, protected):
        return found[0]
    return None


def check(raw: str) -> str | None:
    """The reason a command edits protected files, or None; `cd`, `pushd` and `popd` move where later relative paths start."""
    cwd, saved, known = "", [], {}
    for parsed in commands(raw):
        for name, value in parsed.env.items():
            known[name] = expand(value, known)
        cmd = parsed._replace(args=[expand(a, known) for a in parsed.args], writes=[expand(w, known) for w in parsed.writes])
        if cmd.name in ("cd", "pushd"):
            saved += [cwd] * (cmd.name == "pushd")
            cwd = join(cwd, next((arg for arg in cmd.args if not arg.startswith("-")), ""))
        elif cmd.name == "popd":
            cwd = saved.pop() if saved else ""
        elif (path := written(cmd, cwd)) is not None:
            return REASON.format(path=shown(path))
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"protect-ci-workflows: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
