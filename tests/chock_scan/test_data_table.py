"""chock_scan.data_table: parse, envelope and load. Every refusal raises; nothing returns an empty table."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
from trees import ROOT

from .dtcommon import CORPUS, IDS, SOURCES, load_module, table, write

ROWS = {"rows"}
RLO = chr(0x202E)
ZWSP = chr(0x200B)


@pytest.fixture
def tmp_path(tmp_path: Path) -> Path:
    """A `data` folder: the only place the loader reads a table from."""
    folder = tmp_path / "data"
    folder.mkdir()
    return folder


@pytest.fixture(params=SOURCES, ids=IDS)
def dt_(request: pytest.FixtureRequest) -> ModuleType:
    return load_module(request.param)


def _problems(dt_: ModuleType, path: Path, **kw: object) -> list[str]:
    with pytest.raises(dt_.TableError) as err:
        dt_.load(path, **{"kind": "curated", "schema": 1, "keys": ROWS, **kw})
    assert err.value.name == str(path)
    assert str(err.value).startswith(f"{path}: ")
    return err.value.problems


def test_a_valid_table_loads_whole(dt_: ModuleType, tmp_path: Path) -> None:
    doc = dt_.load(write(tmp_path / "t.json", table()), kind="curated", schema=1, keys=ROWS)
    assert doc == table()


@pytest.mark.parametrize(
    ("name", "kind", "schema", "keys"),
    [
        ("ioc.json", "ioc", 1, {"entries"}),
        ("topn-npm.json", "top-n", 1, {"names"}),
        ("curated-sources.json", "curated", 2, {"verdicts"}),
    ],
)
def test_the_corpus_tables_load(dt_: ModuleType, name: str, kind: str, schema: int, keys: set[str]) -> None:
    assert dt_.load(CORPUS / name, kind=kind, schema=schema, keys=keys)["kind"] == kind


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("", "not valid JSON"),
        ("[]", "must be a JSON object"),
        ('"x"', "must be a JSON object"),
        ("null", "must be a JSON object"),
        ('{"a": 1,}', "not valid JSON"),
        ('{"a": NaN}', "NaN is not JSON"),
        ('{"a": -Infinity}', "-Infinity is not JSON"),
        ('{"as_of": "2026-01-01", "as_of": "2020-01-01"}', "duplicate keys: 'as_of'"),
        ('{"a": {"k": 1, "\\u006b": 2}}', "duplicate keys: 'k'"),
        ('{"a": 1} {"b": 2}', "not valid JSON"),
        ("{'a': 1}", "not valid JSON"),
        ('{"a": 1} // c', "not valid JSON"),
        ('{"a": ' + "1" * 5000 + "}", "not valid JSON"),
        ("[" * 100_000 + "]" * 100_000, "nested deeper than 32"),
        ('{"a":' * 40 + "1" + "}" * 40, "nested deeper than 32"),
    ],
)
def test_parse_refuses_what_is_not_one_plain_json_object(dt_: ModuleType, text: str, needle: str) -> None:
    with pytest.raises(dt_.TableError) as err:
        dt_.parse(text, "t")
    assert needle in str(err.value)


def test_nesting_up_to_the_cap_parses(dt_: ModuleType) -> None:
    assert dt_.parse('{"a":' * 31 + "[]" + "}" * 31)
    with pytest.raises(dt_.TableError, match="deeper"):
        dt_.parse('{"a":' * 32 + "[]" + "}" * 32)


def test_many_duplicates_are_named_once_and_capped(dt_: ModuleType) -> None:
    text = "{" + ",".join(f'"k{i % 20}": 1' for i in range(2000)) + "}"
    with pytest.raises(dt_.TableError) as err:
        dt_.parse(text)
    assert str(err.value).count("'k") == 10


@pytest.mark.parametrize(
    ("override", "needle"),
    [
        ({"schema": None}, "missing envelope keys: schema"),
        ({"kind": None, "as_of": None}, "missing envelope keys: as_of, kind"),
        ({"schema": 0}, "schema must be an integer"),
        ({"schema": True}, "schema must be an integer"),
        ({"schema": 1.0}, "schema must be an integer"),
        ({"schema": "1"}, "schema must be an integer"),
        ({"kind": "IOC"}, "kind must be one of curated, ioc, top-n"),
        ({"kind": ["ioc"]}, "kind must be one of"),
        ({"as_of": "2026-1-5"}, "as_of must be a YYYY-MM-DD"),
        ({"as_of": "2026-02-30"}, "as_of must be"),
        ({"as_of": "2026-01-15T00:00"}, "as_of must be"),
        ({"as_of": "20260115"}, "as_of must be"),
        ({"as_of": "".join(map(chr, (0xFF12, 0xFF10, 0xFF12, 0xFF16))) + "-01-15"}, "as_of must be"),
        ({"as_of": "2026-01-15\n"}, "as_of must be"),
        ({"as_of": "2019-12-31"}, "on or after 2020-01-01"),
        ({"as_of": 20260115}, "as_of must be"),
        ({"source": ""}, "source must be 1..500 printable"),
        ({"source": "x" * 501}, "source must be 1..500"),
        ({"source": f"see{RLO}evil"}, "printable"),
        ({"source": f"see{ZWSP}x"}, "printable"),
        ({"source": "line\nbreak"}, "printable"),
        ({"source": 42}, "source must be"),
        ({"source": ["https://example.org"]}, "source must be"),
        ({"source": "http://example.org/x"}, "no URL scheme but https://"),
        ({"source": "see http://evil.example"}, "no URL scheme but https://"),
        ({"source": "ftp://evil.example"}, "no URL scheme but https://"),
        ({"source": "xhttps://evil.example"}, "no URL scheme but https://"),
        ({"source": " https://example.org"}, "no outer spaces"),
        ({"source": "a citation "}, "no outer spaces"),
        ({"source": "https://"}, "https:// URL"),
        ({"source": "https://example.org/a b"}, "https:// URL"),
        ({"source": "HTTPS://localhost"}, "no URL scheme but https://"),
        ({"source": "https://localhost"}, "https:// URL with a host"),
        ({"source": "12-34"}, "a citation in words"),
        ({"source": {}}, "source must not be an empty object"),
        ({"source": {"Bad Id": "https://example.org"}}, "source id 'Bad Id' must be kebab-case"),
        ({"source": {"a": "http://example.org"}}, "source.a must have no outer spaces, and no URL scheme"),
        ({"source": {"X" * 200: "https://a.b"}}, "source id '" + "X" * 76 + "..." + " must be kebab-case"),
        ({"source": {"a": None}}, "source.a must be 1..500"),
    ],
)
def test_a_bad_envelope_is_refused_by_name(dt_: ModuleType, tmp_path: Path, override: dict, needle: str) -> None:
    found = _problems(dt_, write(tmp_path / "t.json", table(**override)))
    assert any(needle in p for p in found), found


def test_every_envelope_problem_is_reported_at_once(dt_: ModuleType, tmp_path: Path) -> None:
    bad = table(schema=0, kind="x", as_of="soon", source="")
    assert len(_problems(dt_, write(tmp_path / "t.json", bad))) == 4


@pytest.mark.parametrize(
    "source",
    [
        "https://example.org",
        "https://cwe.mitre.org/data/downloads.html?x=1#y",
        "MITRE CWE List v4.14 (2024-02-29), https://cwe.mitre.org/data/downloads.html",
        {"r11": "open-coder-ai/org-plan:discovery/x.md", "sr-readme": "https://github.com/a/b"},
    ],
)
def test_a_url_a_citation_or_an_object_of_either_is_a_source(dt_: ModuleType, tmp_path: Path, source: object) -> None:
    assert dt_.load(write(tmp_path / "t.json", table(source=source)), kind="curated", schema=1, keys=ROWS)


@pytest.mark.parametrize(
    ("override", "kw", "needle"),
    [
        ({"kind": "top-n"}, {}, "kind is top-n, expected curated"),
        ({}, {"kind": "ioc"}, "kind is curated, expected ioc"),
        ({"schema": 2}, {}, "schema is 2, expected 1"),
        ({"rows": None}, {}, "missing keys: rows"),
        ({"extra": 1}, {}, "unknown keys: 'extra'"),
        ({"rows" + ZWSP: 1}, {}, "unknown keys: 'rows\\u200b'"),
        ({"Rows": 1}, {}, "unknown keys: 'Rows'"),
    ],
)
def test_the_caller_pins_kind_schema_and_payload_keys(
    dt_: ModuleType, tmp_path: Path, override: dict, kw: dict, needle: str
) -> None:
    found = _problems(dt_, write(tmp_path / "t.json", table(**override)), **kw)
    assert needle in found


def test_the_payload_check_runs_once_keys_are_right(dt_: ModuleType, tmp_path: Path) -> None:
    path = write(tmp_path / "t.json", table())
    assert _problems(dt_, path, check=lambda d: [f"{len(d['rows'])} rows"]) == ["2 rows"]
    assert _problems(dt_, path, check=lambda _d: "one problem") == ["one problem"]
    assert dt_.load(path, kind="curated", schema=1, keys=ROWS, check=lambda _d: [])
    called: list[dict] = []
    _problems(dt_, write(tmp_path / "u.json", table(extra=1)), check=called.append)
    assert called == []


@pytest.mark.parametrize("exc", [KeyError("k"), TypeError("t"), ValueError("v"), AttributeError("a"), IndexError(1)])
def test_a_check_that_trips_on_the_payload_is_a_table_error(dt_: ModuleType, tmp_path: Path, exc: Exception) -> None:
    def check(_doc: dict) -> list[str]:
        raise exc

    found = _problems(dt_, write(tmp_path / "t.json", table()), check=check)
    assert found == [f"payload check failed: {type(exc).__name__}: {exc}"]


@pytest.mark.parametrize(
    ("kw", "needle"),
    [
        ({"kind": "IOC"}, "kind must be one of"),
        ({"schema": "1"}, "schema must be an int"),
        ({"schema": True}, "schema must be an int"),
        ({"keys": {"rows", "as_of"}}, "must not be envelope keys: as_of"),
    ],
)
def test_a_caller_error_is_a_value_error_before_any_read(dt_: ModuleType, kw: dict, needle: str) -> None:
    with pytest.raises(ValueError, match=needle) as err:
        dt_.load("/nonexistent/t.json", **{"kind": "curated", "schema": 1, "keys": ROWS, **kw})
    assert not isinstance(err.value, dt_.TableError)


@pytest.mark.parametrize(
    ("content", "needle"),
    [(b"\0{}", "binary"), (b"\xff{}", "not UTF-8"), (b" " * 10, "not valid JSON")],
)
def test_an_unreadable_file_is_a_table_error(dt_: ModuleType, tmp_path: Path, content: bytes, needle: str) -> None:
    path = tmp_path / "t.json"
    path.write_bytes(content)
    assert any(needle in p for p in _problems(dt_, path))


def test_a_missing_file_a_folder_and_an_oversized_file_are_table_errors(dt_: ModuleType, tmp_path: Path) -> None:
    assert "unreadable" in _problems(dt_, tmp_path / "absent.json")[0]
    (tmp_path / "dir.json").mkdir()
    assert "not a regular file" in _problems(dt_, tmp_path / "dir.json")[0]
    path = write(tmp_path / "t.json", table())
    with pytest.raises(dt_.TableError, match="larger than 10 bytes"):
        dt_.read(path, limit=10)


def test_a_leading_bom_and_crlf_are_read_as_text(dt_: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(table(), indent=1).replace("\n", "\r\n").encode())
    assert dt_.load(path, kind="curated", schema=1, keys=ROWS) == table()


def test_the_module_is_stdlib_only_and_imports_only_safe_read_from_lib() -> None:
    tree = ast.parse((ROOT / "lib" / "chock_scan" / "data_table.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and not n.level}
    assert {n.split(".")[0] for n in names} <= set(sys.stdlib_module_names)
    local = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level}
    assert local == {"safe_read"}
