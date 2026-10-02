"""block-no-verify's readers of the ways a command switches git hooks off (stdlib only)."""

from .flags import HOOK_SUBS, rebase_execs, skips_verify
from .gitargs import HOOKS_KEY, aliases, asks_for, config_pairs, config_writes, env_asks, submodule_scripts
from .managers import (
    DECLARERS,
    END,
    PS_PATH,
    PS_SETTERS,
    SHELLS,
    declared,
    env_hits,
    launched,
    normalise,
    uninstalls,
    without_bodies,
)

__all__ = [
    "DECLARERS",
    "END",
    "HOOKS_KEY",
    "HOOK_SUBS",
    "PS_PATH",
    "PS_SETTERS",
    "SHELLS",
    "aliases",
    "asks_for",
    "config_pairs",
    "config_writes",
    "declared",
    "env_asks",
    "env_hits",
    "launched",
    "normalise",
    "rebase_execs",
    "skips_verify",
    "submodule_scripts",
    "uninstalls",
    "without_bodies",
]
