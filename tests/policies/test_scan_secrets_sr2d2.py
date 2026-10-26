"""scan-secrets: `-p<password>` is a password only for the tools whose -p carries one, and only within that command."""

from __future__ import annotations

import re

import pytest
from policies import scriptkit

PATTERN = re.compile(scriptkit.manifest("scan-secrets")["hook"]["gate"]["params"]["content_pattern"])

# fmt: off
PASSWORDS = [
    "mariadb -u root -pS3cretPa55 db",  # pragma: allowlist secret
    "mariadb-dump -uroot -pS3cretPa55 db",  # pragma: allowlist secret
    "mariadb-admin -pS3cretPa55 status",  # pragma: allowlist secret
    "mysqlpump -pS3cretPa55 db",  # pragma: allowlist secret
    "mysqlimport -u root -pS3cretPa55 db f.txt",  # pragma: allowlist secret
    "mysqlcheck -pS3cretPa55 db",  # pragma: allowlist secret
    "mysqlshow -pS3cretPa55",  # pragma: allowlist secret
    "mariadb -u root -p'S3cretPa55' db",
    "echo start; mysqldump -uroot -pS3cretPa55 db > out.sql",  # pragma: allowlist secret
    "sshpass -p S3cretPa55 ssh host",
    "sshpass -pS3cretPa55 ssh host",  # pragma: allowlist secret
]
SILENT = [
    "mkdir -p /srv/app/data",
    "ssh -p 2222 host",
    "ssh -p2222 host",
    "tar -pxzf backup.tar.gz",
    "cp -pRv build dist",
    "mysqldump db | ssh -p2222 backup",
    "mysqldump db && tar -pxzf backup.tar.gz",
    "mariadb-dump db; cp -prv out /srv/out",
    "mysql -u root -p app",
    "mariadb -h db -P 3306 -u root -p app",
    "mysqldump -u root -p$DB_PASS db",
    "sshpass -p $PASS ssh host",
]
# fmt: on


@pytest.mark.parametrize("line", PASSWORDS)
def test_a_password_flag_of_a_password_tool_is_refused(line: str) -> None:
    assert PATTERN.search(line), line


@pytest.mark.parametrize("line", SILENT)
def test_a_p_flag_of_another_tool_or_command_is_silent(line: str) -> None:
    assert not PATTERN.search(line), line
