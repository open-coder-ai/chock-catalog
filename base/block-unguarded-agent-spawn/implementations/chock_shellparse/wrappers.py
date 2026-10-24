"""The commands that run another command (sudo, env, nice, timeout, xargs ...) and the options they take (stdlib only; shared byte for byte by the guards)."""

from .args import abbreviates
from .quoting import split_words

WIPED = "CHOCK_ENV_WIPED"  # in the env of a command that `env -i` ran: the agent markers are gone
WRAPPERS = {
    name: (frozenset(flags.split()), skip)
    for name, flags, skip in (
        ("sudo", "-u -g -h -p -C -D -R -T -U -r -t --user --group --host --prompt --chdir", 0),
        ("doas", "-u -C", 0),
        ("pkexec", "--user", 0),
        ("env", "-u -C --unset --chdir", 0),
        ("exec", "-a", 0),
        ("nice", "-n --adjustment", 0),
        ("ionice", "-c -n -p -t", 0),
        ("time", "-f -o --format --output", 0),
        ("timeout", "-s -k --signal --kill-after", 1),
        ("xargs", "-a -d -E -I -L -n -P -s --arg-file --delimiter --max-args --max-procs --replace", 0),
        ("stdbuf", "-i -o -e", 0),
    )
} | dict.fromkeys(
    (
        "command",
        "builtin",
        "nohup",
        "setsid",
        "rtk",
        "export",
        "do",
        "then",
        "else",
        "elif",
        "if",
        "{",
        "while",
        "until",
        "!",
    ),
    (frozenset(), 0),
)


def _env_option(word: str, words: list[str], i: int) -> tuple[str, int] | None:
    """For env's -S/--split-string at words[i]: (the string env splits and runs, the index after it); None for any other option."""
    if word.startswith("--"):
        flag, equals, value = word.partition("=")
        if not abbreviates(flag, "--split-string", 4):
            return None
        return (value, i + 1) if equals else (words[i + 1] if i + 1 < len(words) else "", i + 2)
    for at, char in enumerate(word[1:], 1):
        if char in "uC":  # these take the rest of the cluster, or the next word, as a value
            return None
        if char == "S":
            return (word[at + 1 :], i + 1) if word[at + 1 :] else (words[i + 1] if i + 1 < len(words) else "", i + 2)
    return None


def _env_wipes(word: str) -> bool:
    """Whether an env option clears the environment: -i, --ignore-environment (or an unambiguous prefix), a lone -."""
    if word.startswith("--"):
        return abbreviates(word, "--ignore-environment", 10)
    for char in word[1:]:
        if char in "uCS":
            return False
        if char == "i":
            return True
    return word == "-"


def unwrap(name: str, words: list[str]) -> tuple[list[str], bool]:
    """The words after wrapper `name` and its options (env's -S string is split into them), and whether env -i wiped the environment."""
    flags, skip = WRAPPERS[name]
    i, wiped = 0, False
    while i < len(words) and words[i].startswith("-"):
        word = words[i]
        if word == "--":
            i += 1
            break
        if name == "env":
            wiped = wiped or _env_wipes(word)
            if split := _env_option(word, words, i) if len(word) > 1 else None:
                words, i = [*split_words(split[0]), *words[split[1] :]], 0
                continue
        if len(word) == 1:
            if name == "env":
                i += 1
                continue
            break
        i += 2 if word in flags else 1
    return words[i + skip :], wiped
