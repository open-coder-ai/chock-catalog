"""Read a command's arguments the way its tool does (stdlib only; shared byte for byte by the guards)."""


def flags_of(args: list[str]) -> set[str]:
    """Long flags as written and short clusters split apart (-rf gives -r and -f)."""
    found: set[str] = set()
    for arg in args:
        if arg.startswith("--"):
            found.add(arg.split("=", 1)[0])
        elif arg.startswith("-") and len(arg) > 1:
            found.update(f"-{char}" for char in arg[1:])
    return found


def operands(args: list[str]) -> list[str]:
    """Every argument that is not a flag."""
    return [arg for arg in args if not arg.startswith("-")]


def positionals(args: list[str], value_flags: frozenset[str]) -> list[str]:
    """Operands with the values of `value_flags` dropped, so `helm --kube-context prod uninstall` reads `uninstall`."""
    found, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in value_flags
        else:
            found.append(arg)
    return found


def after(items: list[str], word: str) -> str:
    """The item right after the first `word`, or ''."""
    return items[items.index(word) + 1] if word in items and items.index(word) + 1 < len(items) else ""


def abbreviates(flag: str, full: str, floor: int) -> bool:
    """git and PowerShell accept any unambiguous prefix of a long option; `floor` is the shortest that is."""
    return len(flag) >= floor and full.startswith(flag)


def taken(arg: str) -> int:
    """How many words a short-option cluster takes: each `o` or `O` (`-co pipefail`, `-Oc extglob`, `+o errexit`) takes the next."""
    return 0 if arg[1:2] == "-" else sum(ch in "oO" for ch in arg[1:])
