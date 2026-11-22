"""scan-secrets: a password typed into a command is refused wherever the command is saved, JSON-escaped quotes included.

An agent that is told "don't ask again" saves the exact command into its local settings file as a JSON string, so a
quote after the marker reaches the gate as a backslash and a quote. The made-up value matches no provider's format.
"""

from __future__ import annotations

import json
import re

import pytest
from policies import scriptkit

PATTERN = re.compile(scriptkit.manifest("scan-secrets")["hook"]["gate"]["params"]["content_pattern"])
PW = "Zq7vLm2xK9pRt4Wb"
HOST = "db.acme-demo.net"

# `{pw}` is the credential slot; the quoted forms are the ones a shell accepts around it.
SHAPES = [
    "PGPASSWORD={pw} psql -h " + HOST + " -U app -d prod",
    "PGPASSWORD='{pw}' psql -h " + HOST + " -U app -d prod",
    'PGPASSWORD="{pw}" psql -h ' + HOST + " -U app -d prod",
    "sshpass -p {pw} ssh root@" + HOST + " uptime",
    "sshpass -p '{pw}' ssh root@" + HOST + " uptime",
    'sshpass -p "{pw}" ssh root@' + HOST + " uptime",
    'sshpass -p"{pw}" ssh root@' + HOST + " uptime",
    "mysql -h " + HOST + " -u app -p{pw} prod",
    "mysql -h " + HOST + " -u app -p'{pw}' prod",
    "mysql -h " + HOST + ' -u app -p"{pw}" prod',
    "mysql -h " + HOST + " -u app --password={pw} prod",
    'curl -H "Authorization: Bearer {pw}" https://' + HOST + "/v1/items",
    "curl -H 'Authorization: Bearer {pw}' https://" + HOST + "/v1/items",
    "psql postgres://app:{pw}@" + HOST + "/prod",
]
# Where a reference or a placeholder stands for the value: none of these is a credential.
SILENT_VALUES = ["$DBPW", "${DBPW}", "changeme", "<password>", "xxxx", "***"]


def settings_file(command: str) -> str:
    """The text of an agent's settings file that allows `command`, as the agent writes it."""
    return json.dumps({"permissions": {"allow": [f"Bash({command})"]}}, indent=2) + "\n"


def forms(command: str) -> list[str]:
    return [command, settings_file(command), f"Ran this against the box:\n\n{command}\n"]


@pytest.mark.parametrize("shape", SHAPES)
def test_a_literal_is_refused_in_a_command_a_settings_file_or_a_note(shape: str) -> None:
    for text in forms(shape.format(pw=PW)):
        assert PATTERN.search(text), text


@pytest.mark.parametrize("value", SILENT_VALUES)
@pytest.mark.parametrize("shape", SHAPES)
def test_a_reference_or_placeholder_stays_silent(shape: str, value: str) -> None:
    for text in forms(shape.format(pw=value)):
        assert not PATTERN.search(text), text


@pytest.mark.parametrize(
    "line",
    [
        "mysql -h " + HOST + " -u app -p prod",
        "mysql -h " + HOST + " -u app -p 'prod'",
        "mysql -h " + HOST + " -u app --password prod",
        'sshpass -p "$DBPW" ssh root@' + HOST,
        "PGPASSWORD=$(cat /run/secrets/db) psql -h " + HOST,
    ],
)
def test_a_prompt_or_a_lookup_is_silent(line: str) -> None:
    for text in forms(line):
        assert not PATTERN.search(text), text
