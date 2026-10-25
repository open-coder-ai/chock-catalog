"""block-no-verify 0.5.2: an env -i wipe is read from the parsed command, so every spelling of env counts."""

from __future__ import annotations

import pytest
from policies import guardkit

BLOCK, OK = 1, 0
NO_VERIFY = guardkit.load_guard("block-no-verify")


@pytest.mark.parametrize(
    "raw",
    [
        "env -i PATH=/usr/bin git commit -m x",
        "/usr/bin/env -i PATH=/usr/bin git commit -m x",
        "'env' -i git commit -m x",
        '"/usr/bin/env" --ignore-environment git commit -m x',
        "env --ignore-env git commit -m x",
        "env - git commit -m x",
        "env -0i git commit -m x",
        "env -u HOME -i git push",
        "env -S '-i git commit -m x'",
        "sudo env -i git commit -m x",
    ],
)
def test_a_wipe_in_front_of_a_hook_running_git_command_is_refused(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", raw)
    assert NO_VERIFY.run([]) == BLOCK, raw


@pytest.mark.parametrize(
    "raw",
    [
        "env -i FOO=1 python x.py",
        "env git commit -m x",
        "env -u HOME git commit -m x",
        "env -ui git status",
        "git commit -m 'docs: env -i wipes the markers'",
        "/usr/bin/env -i git status",
    ],
)
def test_other_env_uses_pass(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", raw)
    assert NO_VERIFY.run([]) == OK, raw
