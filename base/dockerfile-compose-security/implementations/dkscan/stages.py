"""Stage-aware Dockerfile rules: which FROM, COPY --from and RUN --mount from= name an external image, and who the final stage runs as.

A name an earlier stage declared (`AS <name>`, any case) or a stage index is not an image. Global
ARGs (before the first FROM) expand in FROM; stage ARGs and ENVs expand in COPY --from, mounts and
USER. A variable with no default is unknown, and an unknown image or user is reported, never
assumed safe. A stage built FROM another stage inherits its user and its variables.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from dkscan import images
from dkscan.dockerfile import Instr
from dkscan.rules import Ctx, Hit

ROOT_USERS = frozenset({"root"})
MOUNT_FROM = re.compile(r"(?:^|[,\s])from=([^,\s]+)")
UNKNOWN = "\x00unknown"
AS_FORM = 3


@dataclass
class Stage:
    name: str
    base: str
    from_line: int
    user: str | None = None
    user_line: int = 0
    user_text: str = ""
    env: dict[str, str | None] = field(default_factory=dict)


def words(args: str) -> list[str]:
    """Shell-like words; a line shlex cannot read falls back to whitespace words."""
    try:
        return shlex.split(args, comments=False)
    except ValueError:
        return args.split()


def env_pairs(args: str) -> list[tuple[str, str]]:
    """ENV's `k=v k2=v2` form, or the legacy `k value...` form."""
    found = words(args)
    if found and "=" not in found[0]:
        return [(found[0], " ".join(found[1:]))]
    return [(name, value) for name, _, value in (word.partition("=") for word in found)]


def is_root(user: str) -> bool:
    name = user.split(":", 1)[0].strip()
    return name.lower() in ROOT_USERS or (name.isdigit() and int(name) == 0)


class Walker:
    """One pass over a Dockerfile's instructions, collecting stage facts and image findings."""

    def __init__(self, ctx: Ctx | None = None) -> None:
        self.ctx = ctx or Ctx()
        self.globals: dict[str, str | None] = {}
        self.stages: list[Stage] = []
        self.names: dict[str, int] = {}
        self.hits: list[Hit] = []

    def stage_ref(self, ref: str) -> int | None:
        if ref.isdigit():
            return int(ref) if int(ref) < len(self.stages) else None
        return self.names.get(ref.lower())

    def scope(self) -> dict[str, str | None]:
        return {**self.globals, **self.stages[-1].env} if self.stages else self.globals

    def image(self, ref: str, instr: Instr, what: str) -> None:
        """Judge one external image reference written in `instr`."""
        if what == "FROM" and self.ctx.pins_elsewhere and images.HP06_FROM.search(instr.raw[0]):
            return
        resolved = images.substitute(ref, self.globals if what == "FROM" else self.scope())
        detail = f"{what} {ref}"
        if resolved is None:
            self.hits.append(Hit("dk-from-unresolved", instr.line, detail, f"{detail}: a variable with no default"))
            return
        verdict = images.judge(resolved)
        if verdict == "floating":
            self.hits.append(Hit("dk-from-floating", instr.line, detail, f"{what} {resolved}: no tag, or latest"))
        elif verdict == "no-digest":
            self.hits.append(Hit("dk-from-no-digest", instr.line, detail, f"{what} {resolved}: tag without digest"))

    def from_(self, instr: Instr) -> None:
        found = words(instr.args)
        ref = found[0] if found else ""
        name = found[2] if len(found) >= AS_FORM and found[1].lower() == "as" else ""
        parent = self.stage_ref(ref)
        if parent is not None:
            up = self.stages[parent]
            stage = Stage(name, up.base, instr.line, up.user, up.user_line, up.user_text, dict(up.env))
        else:
            stage = Stage(name, images.substitute(ref, self.globals) or ref, instr.line)
            if ref:
                self.image(ref, instr, "FROM")
        self.stages.append(stage)
        if name:
            self.names[name.lower()] = len(self.stages) - 1

    def arg(self, instr: Instr) -> None:
        for word in words(instr.args):
            name, eq, value = word.partition("=")
            if not self.stages:
                self.globals[name] = value if eq else None
            else:
                self.stages[-1].env[name] = value if eq else self.globals.get(name)

    def env(self, instr: Instr) -> None:
        if self.stages:
            scope = self.scope()
            for name, value in env_pairs(instr.args):
                scope[name] = self.stages[-1].env[name] = images.substitute(value, scope)

    def user(self, instr: Instr) -> None:
        if self.stages:
            stage = self.stages[-1]
            raw = (words(instr.args) or [""])[0]
            stage.user = images.substitute(raw, self.scope())
            stage.user = UNKNOWN if stage.user is None else stage.user
            stage.user_line, stage.user_text = instr.line, raw

    def sources(self, instr: Instr) -> None:
        """COPY --from=<image> and RUN --mount=...,from=<image> pull an image; a stage does not."""
        refs = [instr.flags["from"]] if instr.keyword == "COPY" and "from" in instr.flags else []
        refs += MOUNT_FROM.findall(instr.flags.get("mount", "")) if instr.keyword == "RUN" else []
        for ref in refs:
            if self.stage_ref(ref) is None:
                self.image(ref, instr, f"{instr.keyword} from")

    def final_user(self) -> Hit | None:
        """The final stage's user: none set (over an image that does not say non-root), unknown, or root."""
        if not self.stages:
            return None
        last = self.stages[-1]
        if last.user is None:
            if images.runs_as_non_root(last.base):
                return None
            return Hit(
                "dk-last-user-root",
                last.from_line,
                "final stage: no USER",
                "the final stage sets no USER, so it runs as root",
            )
        if last.user == UNKNOWN:
            why = f"USER {last.user_text}: a variable with no default"
            return Hit("dk-last-user-root", last.user_line, f"USER {last.user_text}", why)
        if is_root(last.user):
            why = f"the final stage runs as USER {last.user_text}"
            return Hit("dk-last-user-root", last.user_line, f"USER {last.user_text}", why)
        return None


HANDLERS = {"FROM": Walker.from_, "ARG": Walker.arg, "ENV": Walker.env, "USER": Walker.user}


def walk(instrs: list[Instr], ctx: Ctx | None = None) -> list[Hit]:
    walker = Walker(ctx)
    for instr in instrs:
        handler = HANDLERS.get(instr.keyword)
        if handler:
            handler(walker, instr)
        elif instr.keyword in ("COPY", "RUN"):
            walker.sources(instr)
    final = walker.final_user()
    return walker.hits + ([final] if final else [])
