"""GitHub Actions expressions: find each `${{ }}`, read the context paths it names, and say which an attacker writes."""

from __future__ import annotations

import re

OPEN, CLOSE = "${{", "}}"
TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*'?)|(?P<num>0[xX][0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)"
    r"|(?P<id>[A-Za-z_][A-Za-z0-9_-]*)|(?P<op>==|!=|<=|>=|&&|\|\||[.\[\]()!<>,*])|(?P<other>\S))"
)
LITERALS = frozenset({"true", "false", "null"})
COMPARE = frozenset({"==", "!=", "<", ">", "<=", ">="})
BOOL_FUNCS = frozenset({"contains", "startswith", "endswith", "success", "failure", "always", "cancelled"})
DYNAMIC = "?"
MIN_CALL = 3  # name ( )
#: github.event leaves GitHub writes itself: numbers, ids, hashes, enums, booleans, timestamps, URLs and
#: account or repository names (restricted to [A-Za-z0-9._-]). Every other github.event path counts as
#: written by whoever triggered the event, so a field this table has not heard of is untrusted.
SAFE_LEAVES = frozenset(
    {
        "number", "id", "node_id", "sha", "before", "after", "action", "merged", "draft", "state", "url",
        "login", "full_name", "private", "fork", "size", "additions", "deletions", "changed_files",
        "author_association", "type", "visibility", "forced", "created", "deleted", "run_number",
        "run_attempt", "conclusion", "status", "event", "workflow_id", "check_suite_id",
    }
)  # fmt: skip
SAFE_SUFFIXES = ("_sha", "_at", "_url", "_id", "_count")
REPO_SEGMENTS = frozenset({"repository", "repo", "head_repository", "owner", "organization", "sender", "user"})
#: Payload subtrees a caller fills with any text it likes, whatever the leaf is called.
FREE_SUBTREES = frozenset({"inputs", "client_payload"})


def expressions(text: str) -> list[str]:
    """The body of each `${{ ... }}` in order; an unterminated one runs to the end (GitHub refuses it)."""
    found, at = [], text.find(OPEN)
    while at >= 0:
        start = pos = at + len(OPEN)
        end = -1
        while pos < len(text):
            if text[pos] == "'":
                close = text.find("'", pos + 1)
                while close >= 0 and text[close + 1 : close + 2] == "'":
                    close = text.find("'", close + 2)
                pos = len(text) if close < 0 else close + 1
            elif text.startswith(CLOSE, pos):
                end = pos
                break
            else:
                pos += 1
        found.append(text[start:end] if end >= 0 else text[start:])
        at = text.find(OPEN, end + len(CLOSE)) if end >= 0 else -1
    return found


def tokens(expr: str) -> list[tuple[str, str]]:
    """(kind, text) per token: str, num, id, op or other; ids and strings keep their case."""
    # Every alternative is a named group, so each match names its kind.
    return [(str(m.lastgroup), m.group(str(m.lastgroup))) for m in TOKEN.finditer(expr)]


def unquote(text: str) -> str:
    body = text[1:-1] if len(text) > 1 and text.endswith("'") else text[1:]
    return body.replace("''", "'")


def contexts(expr: str) -> list[tuple[str, ...]]:
    """Each context path named, lower-cased: `github.event['issue'].title` is ('github', 'event', 'issue', 'title').

    An index that is not a literal is DYNAMIC and ends the path; `[0]` and `.*` are '*'. A name
    called as a function is not a path; its arguments are read like any other tokens.
    """
    toks = tokens(expr)
    paths: list[tuple[str, ...]] = []
    i = 0
    while i < len(toks):
        kind, text = toks[i]
        after = toks[i + 1][1] if i + 1 < len(toks) else ""
        follows_dot = i > 0 and toks[i - 1][1] == "."
        if kind != "id" or after == "(" or follows_dot or text.lower() in LITERALS:
            i += 1
            continue
        path, i = _path(toks, i)
        paths.append(path)
    return paths


def _path(toks: list[tuple[str, str]], i: int) -> tuple[tuple[str, ...], int]:
    """Read one context path starting at token i; return it and the index after it."""
    path = [toks[i][1].lower()]
    i += 1
    while i < len(toks):
        text = toks[i][1]
        nxt = toks[i + 1] if i + 1 < len(toks) else ("", "")
        if text == "." and (nxt[0] == "id" or nxt[1] == "*"):
            path.append(nxt[1].lower())
            i += 2
        elif (
            text == "[" and i + 2 < len(toks) and toks[i + 2][1] == "]" and (nxt[0] in ("str", "num") or nxt[1] == "*")
        ):
            path.append(unquote(nxt[1]).lower() if nxt[0] == "str" else "*")
            i += 3
        elif text == "[":
            path.append(DYNAMIC)
            return tuple(path), i + 1
        else:
            break
    return tuple(path), i


def event_untrusted(rest: tuple[str, ...]) -> bool:
    """Whether github.event.<rest> may hold text the triggering account wrote."""
    if not rest or DYNAMIC in rest or rest[0] in FREE_SUBTREES:
        return True
    leaf, parent = rest[-1], rest[-2] if len(rest) > 1 else ""
    if leaf in SAFE_LEAVES or leaf.endswith(SAFE_SUFFIXES) or rest == ("ref",):
        return False
    # Set by the base repository's own writers: its branch names, and its own default branch.
    if (leaf == "ref" and parent == "base") or (leaf == "default_branch" and parent == "repository"):
        return False
    return not (leaf == "name" and parent in REPO_SEGMENTS)


def untrusted(
    path: tuple[str, ...], tainted: frozenset[str] = frozenset(), typed: frozenset[str] = frozenset()
) -> bool:
    """Whether a context path can carry attacker-written text into a script.

    `tainted` names the env and matrix entries set from such text (`env.title`, `matrix.title`, or
    `matrix.*` when the whole matrix is computed from it). `typed` names workflow inputs declared
    boolean or number, which GitHub validates.
    """
    if path[:3] == ("github", "event", "inputs"):
        path = ("inputs", *path[3:])
    root, rest = path[0], path[1:]
    if root == "github":
        if not rest or rest[0] in (DYNAMIC, "head_ref"):
            return True
        return rest[0] == "event" and event_untrusted(rest[1:])
    if root == "inputs":
        return len(rest) != 1 or rest[0] not in typed
    if root in ("env", "matrix"):
        if not rest or rest[0] == DYNAMIC:
            return root == "env" or any(t.startswith("matrix.") for t in tainted)
        return f"{root}.{rest[0]}" in tainted or f"{root}.*" in tainted
    return False


def boolean_only(expr: str) -> bool:
    """Whether the expression can only yield a boolean, so no text reaches the script.

    True for one call of a boolean function spanning the whole expression, and for a comparison
    or leading negation outside every bracket with no `&&`/`||` there (`a && b` returns b, not a
    boolean). A comparison inside a call's arguments (`format('{0}{1}', title, 1 == 1)`) does not count.
    """
    toks = tokens(expr)
    top: set[str] = set()
    depth = 0
    for kind, text in toks:
        depth += (text in "([") - (text in ")]") if kind == "op" else 0
        if depth == 0 and kind == "op":
            top.add(text)
    if not toks or "&&" in top or "||" in top:
        return False
    if top & COMPARE or toks[0][1] == "!":
        return True
    first = toks[0]
    if first[0] != "id" or first[1].lower() not in BOOL_FUNCS or len(toks) < MIN_CALL or toks[1][1] != "(":
        return False
    depth = 0
    for index, (_, text) in enumerate(toks[1:], 1):
        depth += (text == "(") - (text == ")")
        if depth == 0:
            return index == len(toks) - 1
    return False


def injected(text: str, tainted: frozenset[str] = frozenset(), typed: frozenset[str] = frozenset()) -> list[str]:
    """Each expression in `text` that puts attacker-written text where it is expanded, whitespace-normalized."""
    out = []
    for expr in expressions(text):
        if boolean_only(expr):
            continue
        if any(untrusted(path, tainted, typed) for path in contexts(expr)):
            out.append(" ".join(expr.split()))
    return out


def names(text: str, root: str) -> list[tuple[str, ...]]:
    """Every context path under `root` named anywhere in the expressions of `text`."""
    return [path for expr in expressions(text) for path in contexts(expr) if path[0] == root]


def string_literals(expr: str) -> list[str]:
    return [unquote(text) for kind, text in tokens(expr) if kind == "str"]
