"""chock_scan.data_table: where a table may live, number overflow, caller type errors, and message hygiene."""

from __future__ import annotations

import time
from pathlib import Path
from types import ModuleType

import pytest

from .dtcommon import IDS, SOURCES, load_module, table, write

ROWS = {"rows"}


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
    return err.value.problems


@pytest.mark.parametrize("number", ["1e400", "-1e400", "1" * 400 + ".0"])
def test_a_number_that_overflows_to_infinity_is_refused(dt_: ModuleType, number: str) -> None:
    with pytest.raises(dt_.TableError, match="overflows to"):
        dt_.parse('{"rows": [' + number + "]}")


def test_a_large_finite_float_parses(dt_: ModuleType) -> None:
    assert dt_.parse('{"rows": [1e300, -0.5]}') == {"rows": [1e300, -0.5]}


@pytest.mark.parametrize(
    "rel",
    [
        *("t.json", "data/sub/t.json", "Data/t.json", "datas/t.json"),
        *("data/t.json5", "data/t.jsonc", "data/t.JSON", "data/t.json ", "data/t"),
    ],
)
def test_a_table_outside_a_data_folder_or_not_named_json_is_refused(dt_: ModuleType, tmp_path: Path, rel: str) -> None:
    path = tmp_path.parent / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    write(path, table())
    assert _problems(dt_, path) == ["a table must be a *.json file directly in a folder named data"]


def test_a_symlinked_table_or_data_folder_is_refused(dt_: ModuleType, tmp_path: Path) -> None:
    real = write(tmp_path / "real.json", table())
    (tmp_path / "link.json").symlink_to(real)
    other = tmp_path.parent / "elsewhere" / "data"
    other.mkdir(parents=True)
    (tmp_path.parent / "linked").mkdir()
    (tmp_path.parent / "linked" / "data").symlink_to(other, target_is_directory=True)
    write(other / "t.json", table())
    expected = ["a table and its data folder must not be symlinks"]
    assert _problems(dt_, tmp_path / "link.json") == expected
    assert _problems(dt_, tmp_path.parent / "linked" / "data" / "t.json") == expected
    assert dt_.load(real, kind="curated", schema=1, keys=ROWS)


def test_keys_as_one_string_or_kind_as_a_list_is_a_type_error(dt_: ModuleType) -> None:
    with pytest.raises(TypeError, match="not the string 'rows'"):
        dt_.load("data/t.json", kind="curated", schema=1, keys="rows")
    with pytest.raises(ValueError, match="kind must be one of"):
        dt_.load("data/t.json", kind=["ioc"], schema=1, keys=ROWS)


@pytest.mark.parametrize("exc", [ZeroDivisionError("z"), OverflowError("o"), RecursionError("r")])
def test_arithmetic_and_recursion_in_a_check_are_table_errors(dt_: ModuleType, tmp_path: Path, exc: Exception) -> None:
    def check(_doc: dict) -> list[str]:
        raise exc

    assert _problems(dt_, write(tmp_path / "t.json", table()), check=check)[0].startswith("payload check failed")


def test_many_unknown_keys_are_capped_and_escaped(dt_: ModuleType, tmp_path: Path) -> None:
    extra = {f"k{i:03}\x1b": 1 for i in range(50)}
    (found,) = _problems(dt_, write(tmp_path / "t.json", table(**extra)))
    assert found.count("'k") == 10
    assert "\x1b" not in found
    assert "\\x1b" in found


def test_a_path_through_dot_dot_is_refused(dt_: ModuleType, tmp_path: Path) -> None:
    write(tmp_path / "t.json", table())
    assert _problems(dt_, tmp_path / ".." / "data" / "t.json") == ["a table path must not hold .."]


def test_a_long_run_of_scheme_characters_in_sources_is_linear(dt_: ModuleType, tmp_path: Path) -> None:
    sources = {f"s{i}": "a" * 500 for i in range(16_000)}
    path = write(tmp_path / "t.json", table(source=sources))
    start = time.monotonic()
    assert dt_.read(path)["source"] == sources
    assert time.monotonic() - start < 2
