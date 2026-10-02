"""Load the shapes table (verbs, flags, paths as data, decision D7) and check its payload."""

import re
from functools import cache
from pathlib import Path

from chock_scan import data_table

LISTS = ("stops", "launchers", "write_exempt", "downloaders", "detachers", "iocs")
PATH_LISTS = ("file_paths", "dir_paths")
REGEXES = ("setid_symbolic", "setid_numeric", "url_arg")
MAPS = ("value_flags", "runners")
KEYS = (*LISTS, *PATH_LISTS, *REGEXES, *MAPS, "rules")
LEVELS = ("block", "ask")
PATH = Path(__file__).resolve().parent / "data" / "shapes.json"


def strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def regex(value: object) -> bool:
    try:
        re.compile(value)
    except (re.error, TypeError):
        return False
    return True


def rule_ok(rule: dict) -> bool:
    """A rule names its programs, a level, the verb phrases and a reason; its optional parts have the right shape."""
    try:
        when = rule.get("when", {})
        optional = [regex(rule.get("config_key", "")), regex(when.get("arg_regex", ""))]
        return (
            strings(rule["prog"])
            and rule["level"] in LEVELS
            and all(strings(verb) for verb in rule["verbs"])
            and isinstance(rule["why"], str)
            and strings(rule.get("unless", []))
            and strings(when.get("flags", []))
            and all(strings(v) for v in when.get("values", {}).values())
            and all(optional)
        )
    except (KeyError, AttributeError, TypeError):
        return False


def problems(doc: dict) -> list[str]:
    found = [f"{key} is not a list of strings" for key in LISTS if not strings(doc[key])]
    found += [f"{key} is not a list of expressions" for key in PATH_LISTS if not all(map(regex, doc[key]))]
    found += [f"{key} is not an expression" for key in REGEXES if not regex(doc[key])]
    for key in MAPS:
        if not isinstance(doc[key], dict) or not all(strings(value) for value in doc[key].values()):
            found.append(f"{key} is not a map of lists")
    found += [f"rules[{i}] is malformed" for i, rule in enumerate(doc["rules"]) if not rule_ok(rule)]
    return found


def load(path: Path = PATH) -> dict:
    return data_table.load(path, kind="curated", schema=1, keys=KEYS, check=problems)


@cache
def table() -> dict:
    return load()
