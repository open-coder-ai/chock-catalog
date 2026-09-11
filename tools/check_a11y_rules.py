#!/usr/bin/env python3
"""Fail if the shipped accessibility guard misjudges any rule its own data declares."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "base" / "no-a11y-regression" / "implementations" / "no-a11y-regression-pre-commit.py"

#: A name no noise rule could mistake for placeholder wording.
REAL_NAME = "Quarterly revenue by region"
#: Sources satisfied by a name-bearing child rather than an attribute.
CHILD_SOURCES = {"legend-text": "legend", "caption-text": "caption", "title-child": "title"}
#: A source the markup cannot withhold: the platform supplies the name either way.
ALWAYS_SATISFIED = "implicit-default"
#: A WCAG success criterion: one to two digits per level, as `1.1.1` or `4.1.2`.
CRITERION = re.compile(r"^\d\.\d{1,2}\.\d{1,2}$")

#: Config keys this module exercises. The guard's source is read for the keys it actually
#: consults, so a rule file that grows a key the guard reads fails here until it is covered.
COVERED_SPEC = {"requirements", "void_elements", "suppressible", "suppressing", "component_name_props",
                "markup_suffixes"}
COVERED_NOISE = {"words", "min_length", "file_extensions", "by_tag"}
#: Data files the guard must not read: their entries are records, not verdicts.
RECORDED = ("rules.json", "aria_tables.json", "jurisdictions.json")


def load_guard() -> object:
    """Import the shipped script. Hyphenated, and its dataclass resolves through sys.modules."""
    spec = importlib.util.spec_from_file_location("shipped_a11y_guard", GUARD)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {GUARD}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Probe:
    """Runs the guard over synthesised revisions and records every disagreement, not the first."""

    def __init__(self, guard: object) -> None:
        self.guard = guard
        self.spec = guard.SPEC
        self.noise = guard.NOISE
        self.required = guard.REQUIRED
        self.void = set(self.spec["void_elements"])
        self.failures: list[str] = []
        self.checked = 0

    def _refused(self, before: str, after: str) -> bool:
        return any(row["action"] == self.guard.DENY for row in self.guard.evaluate(before, after))

    def refuses(self, label: str, before: str, after: str) -> None:
        self.checked += 1
        if not self._refused(before, after):
            self.failures.append(f"{label}: allowed a break\n      was: {before}\n      now: {after}")

    def allows(self, label: str, before: str, after: str) -> None:
        self.checked += 1
        if self._refused(before, after):
            self.failures.append(f"{label}: refused a correct change\n      was: {before}\n      now: {after}")

    def assert_that(self, condition: bool, complaint: str) -> None:
        """For the claims that are about the data rather than about a verdict."""
        self.checked += 1
        if not condition:
            self.failures.append(complaint)

    def element(self, tag: str, attrs: dict[str, str], inner: str = "") -> str:
        rendered = " ".join(f'{k}="{v}"' for k, v in attrs.items())
        opened = f"<{tag} {rendered}".rstrip() + ">"
        return opened if tag in self.void else f"{opened}{inner}</{tag}>"

    def synthesise(self, tag: str, rule: dict, *, named: bool, extra: dict[str, str] | None = None) -> str:
        """Minimal markup for `tag` that does or does not satisfy the rule as the table writes it."""
        attrs: dict[str, str] = {"data-testid": f"probe-{tag}"}
        attrs.update(extra or {})
        if when := rule.get("only_when"):
            attrs[when["attr"]] = when.get("equals", "/somewhere")

        if not named:
            return self.element(tag, attrs)

        source = next(s for s in rule["from"] if s != ALWAYS_SATISFIED)
        if source == "text":
            return self.element(tag, attrs, REAL_NAME)
        if source in CHILD_SOURCES:
            child = CHILD_SOURCES[source]
            return self.element(tag, attrs, f"<{child}>{REAL_NAME}</{child}>")
        if source == "label-for":
            attrs["id"] = f"probe-{tag}-id"
            return f'<label for="{attrs["id"]}">{REAL_NAME}</label>' + self.element(tag, attrs)
        attrs[source] = REAL_NAME
        return self.element(tag, attrs)


def requirement_rows(required: dict) -> list[tuple[str, str, dict]]:
    """One row per requirement, plus one per `by_type` variant, labelled as the table writes it."""
    rows: list[tuple[str, str, dict]] = []
    for tag, rule in required.items():
        rows.append((tag, tag, rule))
        for type_name, override in (rule.get("by_type") or {}).items():
            rows.append((f"{tag}[type={type_name}]", tag, {**rule, **override, "_type": type_name}))
    return rows


def losable(rule: dict) -> bool:
    """Whether the rule can be unmet at all: an exempt or platform-named row cannot."""
    return not rule.get("optional") and rule.get("needs") != "none" and ALWAYS_SATISFIED not in rule["from"]


def check_requirements(p: Probe) -> None:
    """Three claims per row: losing the name is refused, meeting it is not, and no change is silent."""
    for label, tag, rule in requirement_rows(p.required):
        extra = {"type": rule["_type"]} if "_type" in rule else {}
        named = p.synthesise(tag, rule, named=True, extra=extra)
        unnamed = p.synthesise(tag, rule, named=False, extra=extra)
        if losable(rule):
            p.refuses(f"<{label}> losing the {rule['needs']} it requires", named, unnamed)
        p.allows(f"<{label}> meeting its requirement", unnamed, named)
        p.allows(f"<{label}> compared to itself", named, named)


def check_provenance(p: Probe) -> None:
    """A generated case proves the guard acts on a row, never that the row should exist."""
    for label, _, rule in requirement_rows(p.required):
        p.assert_that(
            bool(CRITERION.match(str(rule.get("wcag", "")))),
            f"<{label}>: wcag {rule.get('wcag')!r} is not a success criterion",
        )
        anchor = str(rule.get("spec", ""))
        p.assert_that(
            anchor.split("#", 1)[0] in p.spec["specs"],
            f"<{label}>: spec {anchor!r} names no spec this rule file lists",
        )


def check_suppressions(p: Probe) -> None:
    """Marking a named element decorative retracts a statement, however the markup says it."""
    suppressions = [("aria-hidden", p.spec["suppressing"]["aria-hidden"])]
    suppressions += [("role", role) for role in p.spec["suppressing"]["role"]]
    for tag in p.spec["suppressible"]:
        rule = p.required[tag]
        named = p.synthesise(tag, rule, named=True)
        for attr, value in suppressions:
            suppressed = p.synthesise(tag, rule, named=False, extra={attr: value})
            p.refuses(f"<{tag}> marked {attr}={value}", named, suppressed)
    for tag in p.spec["suppressing"]["empty_alt"]:
        named = p.synthesise(tag, p.required[tag], named=True)
        emptied = p.element(tag, {"data-testid": f"probe-{tag}", "alt": ""})
        p.refuses(f'<{tag}> with its alt emptied', named, emptied)


def check_components(p: Probe) -> None:
    """A component is never required to have a name, so only losing one may be refused."""
    for prop in p.spec["component_name_props"]:
        before = f'<Widget data-testid="w" {prop}="{REAL_NAME}" />'
        p.refuses(f"<Widget> losing {prop}", before, '<Widget data-testid="w" />')
        p.refuses(f"<Widget> with {prop} emptied", before, f'<Widget data-testid="w" {prop}="" />')
        p.allows(f"<Widget> gaining {prop}", "<p>x</p>", before)
    p.allows("<Widget> that never carried a name", '<Widget data-testid="w" />', '<Widget data-testid="w" edited="1" />')


def check_void_elements(p: Probe) -> None:
    """Written without a slash a void element looks open, and everything after reads as its child."""
    for void in sorted(p.void):
        trailing = '<a href="/pricing" data-testid="link">See pricing</a>'
        before = f"<{void}>{trailing}"
        after = f'<{void}><a href="/pricing" data-testid="link"></a>'
        p.refuses(f"<{void}> swallowing the element after it", before, after)


def check_noise(p: Probe) -> None:
    """A name supplied as a fix that names nothing is not a fix."""
    bare_img = '<img data-testid="i" src="/chart.png">'
    for word in p.noise["words"]:
        p.refuses(f"alt={word!r}", bare_img, f'<img data-testid="i" src="/chart.png" alt="{word}">')
    for extension in p.noise["file_extensions"]:
        filename = f"quarterly-revenue.{extension}"
        p.refuses(f"alt={filename!r}", bare_img, f'<img data-testid="i" src="/chart.png" alt="{filename}">')
    for word in p.noise["by_tag"]["a"]:
        bare_link = '<a data-testid="l" href="/pricing"></a>'
        p.refuses(f"link text {word!r}", bare_link, f'<a data-testid="l" href="/pricing">{word}</a>')
        # The same word on a button: <button>Continue</button> names a button honestly, which is
        # why link noise cannot live in the global list.
        bare_button = '<button data-testid="b"></button>'
        p.allows(f"button label {word!r}", bare_button, f'<button data-testid="b">{word}</button>')


def check_name_length(p: Probe) -> None:
    """min_length catches two characters of alt text; it must not refuse a button saying Go."""
    limit = p.noise["min_length"]
    bare_img = '<img data-testid="i" src="/a.png">'
    p.refuses(
        f"an alt of {limit - 1} characters",
        bare_img,
        f'<img data-testid="i" src="/a.png" alt="{"x" * (limit - 1)}">',
    )
    p.allows(
        f"an alt of {limit + 2} characters",
        bare_img,
        f'<img data-testid="i" src="/a.png" alt="Zq{"x" * limit}">',
    )
    # A row accepting a `text` source is named by the label a reader sees, where a short name is
    # honest. Derived from the data, so a row gaining or losing `text` moves on its own.
    labelled = sorted(tag for tag, rule in p.required.items() if "text" in rule["from"])
    for tag in labelled:
        for label in ("Go", "OK", "No", "Q1"):
            if label.lower() in p.noise["by_tag"].get(tag, []):
                continue
            rule = p.required[tag]
            after = p.synthesise(tag, rule, named=True).replace(REAL_NAME, label)
            p.allows(f"<{tag}> labelled {label!r}", p.synthesise(tag, rule, named=False), after)


def check_every_key_is_covered(p: Probe) -> None:
    """Read the guard's source for the config it consults, so a new read needs a new case here."""
    source = GUARD.read_text(encoding="utf-8")
    read_spec = set(re.findall(r'SPEC\["([^"]+)"\]', source))
    read_noise = set(re.findall(r'NOISE(?:\.get\(|\[)"([^"]+)"', source))
    p.assert_that(
        read_spec <= COVERED_SPEC,
        f"the guard reads element_requirements keys no case exercises: {sorted(read_spec - COVERED_SPEC)}",
    )
    p.assert_that(
        read_noise <= COVERED_NOISE,
        f"the guard reads uninformative_names keys no case exercises: {sorted(read_noise - COVERED_NOISE)}",
    )
    for recorded in RECORDED:
        p.assert_that(recorded not in source, f"{recorded} is now executed; its entries need cases here")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)


def check_the_commit_path(p: Probe) -> None:
    """The half no in-process case reaches: both revisions read from git, and the exit code.

    `evaluate` can be right while the front end reads the wrong revision, skips the file by its
    suffix, or returns the wrong code -- and only the exit code refuses a commit.
    """
    named = '<img src="/chart.png" alt="Quarterly revenue by region">\n'
    emptied = '<img src="/chart.png" alt="">\n'
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _git(repo, "init", "--quiet", ".")
        _git(repo, "config", "user.email", "rules@chock.invalid")
        _git(repo, "config", "user.name", "rules")
        for name, committed, staged, expected, claim in (
            ("page.html", named, emptied, 1, "an emptied alt in a staged .html"),
            ("fix.html", emptied, named, 0, "a staged fix"),
            ("notes.txt", named, emptied, 0, "the same break in a suffix the guard does not read"),
        ):
            (repo / name).write_text(committed, encoding="utf-8")
            _git(repo, "add", name)
            _git(repo, "commit", "--quiet", "-m", f"add {name}")
            (repo / name).write_text(staged, encoding="utf-8")
            _git(repo, "add", name)
            code = subprocess.run(
                [sys.executable, str(GUARD)], cwd=repo, capture_output=True, text=True, check=False
            ).returncode
            p.assert_that(code == expected, f"at commit time, {claim} exited {code} and not {expected}")
            _git(repo, "commit", "--quiet", "--no-verify", "-m", f"edit {name}")


def main() -> int:
    try:
        guard = load_guard()
    except Exception as exc:  # noqa: BLE001 -- any import failure is the same answer: unrunnable
        print(f"Cannot load the shipped guard: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    probe = Probe(guard)
    for check in (
        check_requirements,
        check_provenance,
        check_suppressions,
        check_components,
        check_void_elements,
        check_noise,
        check_name_length,
        check_every_key_is_covered,
        check_the_commit_path,
    ):
        check(probe)

    if probe.failures:
        print(f"The shipped guard misjudges its own rules ({len(probe.failures)} of {probe.checked}):",
              file=sys.stderr)
        for failure in probe.failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nA rule the guard reads with no case here is answered by adding the case; a verdict that "
            "disagrees is answered in the guard, never by deleting the case. A correct change refused is "
            "the worse half -- this guard blocks commits, and a control that fires on a correct change "
            "has failed.",
            file=sys.stderr,
        )
        return 1

    rows = len(requirement_rows(probe.required))
    print(f"The shipped guard matches its rules: {probe.checked} cases over {rows} requirement rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
