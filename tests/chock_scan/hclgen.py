"""Random valid HCL and Terraform JSON with the values and lines a correct scanner must read back (seeded)."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

LETTERS = "abcxyzABZ_"
TAILS = LETTERS + "0189-"
RESERVED = {"for", "in", "if", "true", "false", "null", "endif", "endfor", "else"}
STRING_POOL = [
    '"',
    "\\",
    "$",
    "%",
    "{",
    "}",
    "${",
    "%{",
    "#",
    "//",
    "/*",
    "*/",
    "=",
    " ",
    "\t",
    "\r",
    "\u00e9",
    "\u2003",
    "x",
]
#: Comments carrying text a careless scanner would read as a key, a block, a string or a heredoc.
COMMENT_POOL = ['evil = "x"', "}", "{", 'r "a" {', '"', "<<EOT", "${", "*", "# //"]
MARKER = "EOT_X"
REF = object()  # in a model: a value the scanner must report as COMPUTED
#: Expressions that are not literals, each of which must read as COMPUTED.
REFS = ["var.a", "local.b[0]", 'f(1, "x")', '"${var.c}-x"', "1 + 2", "x ? 1 : 2", "[for v in l : v]", "-x"]


class Ref(str):
    """An expression rendered as written; the model expects COMPUTED in its place."""


class Flush(str):
    """A `<<-` heredoc's decoded value; rendered with every non-blank line indented further."""


@dataclass
class Out:
    """Rendered text, built in pieces, with the line the next piece starts on."""

    rng: random.Random
    parts: list[str] = field(default_factory=list)
    line: int = 1

    def add(self, text: str) -> None:
        self.parts.append(text)
        self.line += text.count("\n")

    def newline(self) -> None:
        self.add(self.rng.choice(["\n", "\r\n"]))

    def gap(self) -> None:
        """Blank lines and whole-line comments between items."""
        for _ in range(self.rng.randrange(3)):
            pick = self.rng.randrange(4)
            if pick == 0:
                self.add(self.rng.choice(["#", "//"]) + " " + self.rng.choice(COMMENT_POOL))
            elif pick == 1:
                self.add(
                    "/* "
                    + self.rng.choice(COMMENT_POOL).replace("*", "")
                    + "\n"
                    + self.rng.choice(COMMENT_POOL).replace("*", "")
                    + " */"
                )
            self.newline()

    def pad(self) -> None:
        self.add(self.rng.choice(["", " ", "  ", "\t", " /* evil = 1 */ "]))


def ident(rng: random.Random) -> str:
    while (name := rng.choice(LETTERS) + "".join(rng.choice(TAILS) for _ in range(rng.randrange(6)))) in RESERVED:
        pass
    return name


def text(rng: random.Random) -> str:
    return "".join(rng.choice(STRING_POOL) for _ in range(rng.randrange(8)))


def quote(value: str, rng: random.Random) -> str:
    out = value.replace("\\", "\\\\").replace('"', '\\"').replace("${", "$${").replace("%{", "%%{")
    out = out.replace("\t", rng.choice(["\t", "\\t"])).replace("\r", "\\r")
    return '"' + out.replace("\u00e9", rng.choice(["\u00e9", "\\u00e9", "\\U000000E9"])) + '"'


def literal(rng: random.Random, depth: int) -> object:
    forms = [
        lambda: text(rng),
        lambda: rng.randrange(-1000, 100000),
        lambda: rng.randrange(1000) + rng.randrange(1, 100) / 100,
        lambda: rng.choice([True, False, None]),
        lambda: "\n".join(rng.choice(["a b", "  x", "${", '"q"', "# h", "EOT", ""]) for _ in range(3)) + "\n",
        lambda: Ref(rng.choice(REFS)),
        lambda: Flush("a b\n" + "".join(rng.choice(["  x\n", "\n", "${y}\n", "\tz\n", "EOT\n"]) for _ in range(3))),
        lambda: tuple(literal(rng, depth + 1) for _ in range(rng.randrange(4))),
        lambda: {
            ident(rng) if rng.random() < 0.5 else text(rng): literal(rng, depth + 1) for _ in range(rng.randrange(4))
        },
    ]
    return rng.choice(forms if depth < 3 else forms[:7])()


def expected(value: object) -> object:
    """What the scanner must read for a generated value: REF wherever a Ref was written."""
    if isinstance(value, Ref):
        return REF
    if isinstance(value, tuple):
        return tuple(expected(v) for v in value)
    if isinstance(value, dict):
        return {k: expected(v) for k, v in value.items()}
    return value


def render(value: object, out: Out) -> bool:
    """Write `value` as HCL; True if it ended a line (a heredoc's closing marker must stand alone)."""
    rng = out.rng
    if isinstance(value, Ref):
        out.add(value)
        return False
    if isinstance(value, str) and value.endswith("\n") and "\r" not in value:
        heredoc(value, out)
        return True
    if isinstance(value, str):
        out.add(quote(value, rng))
    elif value is None or isinstance(value, bool):
        out.add({None: "null", True: "true", False: "false"}[value])
    elif isinstance(value, (int, float)):
        out.add(repr(value))
    elif isinstance(value, tuple):
        out.add("[")
        for item in value:
            if rng.random() < 0.3:
                out.newline()
            render(item, out)
            out.add(",")
            out.pad()
        out.add("]")
    else:
        assert isinstance(value, dict)
        mapping(value, out)
    return False


def mapping(value: dict, out: Out) -> None:
    """An object; items end with a comma or a newline (a heredoc's own newline counts)."""
    rng = out.rng
    out.add("{")
    line_ended = True
    for key, item in value.items():
        out.newline() if line_ended or rng.random() < 0.5 else out.pad()
        out.add(key if _bare(key) else quote(key, rng))
        out.add(rng.choice([" = ", "=", ": "]))
        line_ended = render(item, out) or rng.random() < 0.5
        if not line_ended:
            out.add(",")
    out.newline()
    out.add("}")


def heredoc(value: str, out: Out) -> None:
    """A heredoc decoding to `value`: `<<-` with every non-blank line indented further for a Flush, else `<<`."""
    body = value.replace("${", "$${").replace("%{", "%%{")
    if isinstance(value, Flush):
        pad = out.rng.choice([" ", "    ", "\t"])
        out.add("<<-" + MARKER + "\n" + "\n".join(pad + ln if ln.strip() else ln for ln in body.split("\n")) + MARKER)
    else:
        out.add("<<" + MARKER + "\n" + body + out.rng.choice(["", "  "]) + MARKER)
    out.newline()


def _bare(name: str) -> bool:
    return name[:1] in LETTERS and name.replace("-", "").replace("_", "").isalnum() and name.isascii()


def body(rng: random.Random, out: Out, depth: int) -> dict:
    """Render a body; return the model (attrs with lines, blocks) the scanner must read back."""
    model: dict = {"attrs": {}, "blocks": []}
    for _ in range(rng.randrange(5)):
        out.gap()
        out.pad()
        if rng.random() < 0.6 or depth >= 3:
            key = ident(rng)
            if key in model["attrs"]:
                continue
            value = literal(rng, 0)
            model["attrs"][key] = (expected(value), out.line)
            out.add(key + rng.choice([" = ", "=", "\t=\t"]))
            render(value, out)
        else:
            kind = ident(rng)
            labels = tuple(
                text(rng).replace("\n", "") if rng.random() < 0.5 else ident(rng) for _ in range(rng.randrange(3))
            )
            line = out.line
            out.add(kind + "".join(" " + (lb if _bare(lb) else quote(lb, rng)) for lb in labels))
            out.add(" {")
            out.newline()
            child = body(rng, out, depth + 1)
            out.add("}")
            model["blocks"].append((kind, labels, line, child))
        out.pad()
        if rng.random() < 0.3:
            out.add(rng.choice(["# trailing evil = 1", "// }"]))
        out.newline()
    out.gap()
    return model


def document(seed: int) -> tuple[str, dict]:
    rng = random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret
    out = Out(rng)
    if rng.random() < 0.2:
        out.parts.append("\ufeff")
    model = body(rng, out, 0)
    return "".join(out.parts), model
