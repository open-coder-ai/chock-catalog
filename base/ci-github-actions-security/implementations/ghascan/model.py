"""What a rule reads from a workflow, composite action or Dependabot file: triggers, jobs, steps, env and hits."""

from __future__ import annotations

from typing import NamedTuple

from ghascan import expr
from ghascan.tree import Tree

Path = tuple[str | int, ...]
WORKFLOW, ACTION, DEPENDABOT = "workflow", "action", "dependabot"
FALSY = frozenset({"", "false", "0", "no", "off", "${{ false }}", "${{false}}"})
#: Triggers that run the base repository's workflow, with its secrets and a token that can write,
#: on an event someone outside the repository can cause (zizmor dangerous-triggers).
DANGEROUS = ("pull_request_target", "workflow_run", "issue_comment")
#: Also run in the base repository's context on text an outsider writes.
RISKY = frozenset({*DANGEROUS, "issues", "discussion", "discussion_comment"})
#: Carry text from a pull request or its review into a workflow.
PR_EVENTS = frozenset({"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment"})


class Hit(NamedTuple):
    """One finding before keying: rule id, line, scope (job or file), detail (the stable flagged text), words."""

    rule: str
    line: int
    scope: str
    detail: str
    message: str


class Ctx(NamedTuple):
    """What every rule receives: the document, the file kind, its raw lines, its triggers, the data tables."""

    tree: Tree
    kind: str
    lines: list[str]
    on: set[str]
    tables: dict
    typed: frozenset[str] = frozenset()
    locate: Locator | None = None


class Step(NamedTuple):
    job: str
    path: Path
    uses: str
    run: str | None


def falsy(text: str | None) -> bool:
    return text is not None and " ".join(text.split()).lower() in FALSY


def action_name(uses: str) -> str:
    """`owner/repo[/path]` of a `uses:` value, lower-cased, with the ref dropped."""
    return uses.strip().split("@", 1)[0].strip().lower()


def is_action(uses: str, *names: str) -> bool:
    """Whether `uses` names one of these actions (a sub-path such as actions/cache/restore counts)."""
    name = action_name(uses)
    return any(name == n or name.startswith(n + "/") for n in names)


def triggers(tree: Tree) -> set[str]:
    """Event names under `on:` (a string, a list, or a mapping), lower-cased."""
    found = {n.value.strip().lower() for n in tree.values(("on",))}
    found |= {
        n.value.strip().lower() for key in tree.keys(("on",)) if isinstance(key, int) for n in tree.values(("on", key))
    }
    found |= {str(key).lower() for key in tree.keys(("on",)) if isinstance(key, str)}
    return found - {""}


def typed_inputs(tree: Tree) -> frozenset[str]:
    """Workflow inputs declared `type: boolean` or `type: number` under every event that declares them:
    GitHub validates those, so no text gets in. A name free-text under either event stays untrusted."""
    kinds: dict[str, set[str]] = {}
    for event in ("workflow_dispatch", "workflow_call"):
        for name in tree.keys(("on", event, "inputs")):
            kind = (tree.text(("on", event, "inputs", name, "type")) or "").strip().lower()
            kinds.setdefault(str(name).lower(), set()).add(kind)
    return frozenset(name for name, seen in kinds.items() if seen <= {"boolean", "number"})


def jobs(tree: Tree) -> list[str]:
    return [str(k) for k in tree.keys(("jobs",))]


def steps(tree: Tree, kind: str) -> list[Step]:
    """Every step: each job's in a workflow, `runs.steps` in a composite action."""
    holders = [("(action)", ("runs", "steps"))] if kind == ACTION else [(j, ("jobs", j, "steps")) for j in jobs(tree)]
    out = []
    for job, base in holders:
        for index in tree.keys(base):
            path = (*base, index)
            uses = " ".join(n.value for n in tree.values((*path, "uses")))
            runs = tree.values((*path, "run"))
            out.append(Step(job, path, uses, "\n".join(n.value for n in runs) if runs else None))
    return out


def job_path(step: Step) -> Path:
    return step.path[:-2]


def env_maps(step: Step) -> list[Path]:
    """The env mappings in force for a workflow step: the workflow's, the job's and the step's own."""
    return [("env",), ("jobs", step.job, "env"), (*step.path, "env")]


def env_text(tree: Tree, paths: list[Path]) -> dict[str, str]:
    """Name (upper-cased) to every value written for it across the given env maps, joined."""
    out: dict[str, str] = {}
    for base in paths:
        for key in tree.keys(base):
            text = "\n".join(n.value for n in tree.values((*base, key)))
            name = str(key).upper()
            out[name] = f"{out[name]}\n{text}" if name in out else text
    return out


def all_env_maps(tree: Tree, kind: str) -> list[Path]:
    """Every env mapping in the file, for rules that judge an env setting wherever it is."""
    found = [("env",)] if kind == WORKFLOW else []
    found += [("jobs", j, "env") for j in jobs(tree)]
    found += [(*s.path, "env") for s in steps(tree, kind)]
    found += [("jobs", j, "container", "env") for j in jobs(tree)]
    return found


def with_text(tree: Tree, step: Step, name: str) -> str | None:
    """The step's `with.<name>` as a loader keeps it, or None."""
    return tree.text((*step.path, "with", name))


def with_values(tree: Tree, step: Step, name: str) -> list[str]:
    """Every value written for `with.<name>`, for rules that look for a value."""
    return [n.value for n in tree.values((*step.path, "with", name))]


SUBSTRING, IN_EXPR, WHOLE_LINE = "substring", "in-expr", "whole-line"


class Locator:
    """Finding lines: the nth occurrence of a rule's text in a value, so a waiver on one copy never covers another."""

    def __init__(self, tree: Tree, lines: list[str]) -> None:
        self.tree, self.lines = tree, lines
        self.seen: dict[tuple, int] = {}

    def line(self, rule: str, path: Path, needle: str, *, mode: str = SUBSTRING) -> int:
        key = (rule, path, needle, mode)
        nth = self.seen.get(key, 0)
        self.seen[key] = nth + 1
        return self._find(path, needle, nth, mode)

    def _find(self, path: Path, needle: str, nth: int, mode: str) -> int:
        """The line of the nth occurrence of `needle` within the value at `path`, else the line it starts on.

        The value ends at the next line indented no deeper than its key (a step: than its `-`). Modes:
        SUBSTRING counts the text anywhere on a line; IN_EXPR only inside `${{ }}`, case-insensitively,
        so a comment or key holding the same words is never taken for the finding; WHOLE_LINE counts a
        line whose stripped text is the needle, for rules that flag a script line.
        """
        start = self.tree.line(path)
        head = self.lines[start - 1]
        indent = _indent(head) if path and isinstance(path[-1], int) else len(head) - len(head.lstrip(" -"))
        seen = 0
        for number in range(start, len(self.lines) + 1):
            text = self.lines[number - 1]
            if number > start and text.strip() and _indent(text) <= indent:
                break
            if mode == IN_EXPR:
                seen += sum(body.lower().count(needle.lower()) for body in expr.expressions(text))
            else:
                seen += (text.strip() == needle) if mode == WHOLE_LINE else text.count(needle)
            if seen > nth:
                return number
        return start


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip(" "))


def normalize(text: str) -> str:
    return " ".join(text.split())
