"""Mark what a shell expands before the command is parsed, so a name keeps only the text it would literally hold.

A `$` the shell expands becomes EXPANDED; a whole `${...}`, command substitution, backtick command or process
substitution (`$(...)`, `` `...` ``, `<(...)`) becomes one EXPANDED, and every script inside one is handed back to be
judged on its own. So `"${OUT}/x"` or `"${f// /_}"` is never read as a name, while text the shell keeps
(single-quoted, escaped, spliced from quoted pieces such as `a$\\(id\\)` or `$(true)'a;b'`) stays and is judged.
`$'...'` is decoded and re-quoted, so `$'a\\x3bb'` is judged as `a;b`. Heredoc bodies are copied through untouched.
The same scanner, run nested, finds where a substitution ends, so quotes in its heredocs and comments are tracked.
"""

from __future__ import annotations

import re
import sys

EXPANDED = chr(0xE000)  # a private-use character standing in for expanded text
REPLACEMENT = chr(0xFFFD)  # what a code point past Unicode decodes to
_STARTS = frozenset("@*#?$!-_")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b", "E": "\x1b"}
_ANSI = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c.|.)", re.DOTALL)
# A delimiter word keeps a carriage return, as bash does: under CRLF the delimiter is `EOF\r`.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*((?:'[^'\n]*'|\"[^\"\n]*\"|\\.|[^\s'\"<>|;&()\\]|\r)+)")
_QUOTE_PIECE = re.compile(r"'([^']*)'|\"([^\"]*)\"|\\(.)|([^'\"\\]+)")
_WORD_BEFORE = frozenset(" \t\n;&|()<>")  # bash starts a comment after any metacharacter
MAX_NESTING, MAX_HEREDOCS = 64, 256  # past either the line is refused by the caller, not read
_COMMAND_WORD = re.compile(r"(?:^|[\s;&|(])(?:then|do|else|elif|if|while|until|!|\{|time(?:\s+-p)?|coproc)$")
_CASE_IN = re.compile(r"(?:^|[\s;&|(])case\s+(?:\"[^\"]*\"|'[^']*'|\S+)\s+in\s*$")
_BODY_QUOTES = str.maketrans("'\"`", "\x01\x01\x01")  # still a refused character in an update-ref --stdin name
_BACKTICK_ESCAPE = re.compile(r"\\([$`\\])")
_BACKTICK_ESCAPE_QUOTED = re.compile(r"\\([$`\\\"])")  # inside double quotes bash also drops it before `"`


class UnreadableError(ValueError):
    """The line cannot be read to the end: a substitution never closes, or it holds too much to read in time."""


class TooDeepError(UnreadableError):
    """The line nests substitutions deeper than MAX_NESTING, or holds more than MAX_HEREDOCS heredocs."""


def _ansi_char(match: re.Match[str]) -> str:
    code = match.group(1)
    if code[0] in "xuU":
        number = int(code[1:], 16)
        return chr(number) if number <= sys.maxunicode else REPLACEMENT
    if code[0].isdigit():
        return chr(int(code, 8))
    if code[0] == "c" and code[1:]:
        return chr(ord(code[1]) & 0x1F)
    return _ESCAPES.get(code, code)


def _delimiter(word: str) -> str:
    """A heredoc delimiter as the shell reads it: quoted pieces and escapes joined (`E"O"F` is EOF)."""
    return "".join("".join(piece) for piece in _QUOTE_PIECE.findall(word))


class _Marker:
    """One left-to-right pass that tracks quoting the way the shell does; nested, it stops at its closer."""

    def __init__(self, raw: str, *, powershell: bool, start: int = 0, closer: str = "", nesting: int = 0) -> None:
        if nesting > MAX_NESTING:
            raise TooDeepError
        # Text a nested pass opens with `(` is arithmetic (`$((...))`, `((...))`): `<<` there is a shift.
        arith = closer == ")" and raw[start : start + 1] == "("
        self.nesting, self.start, self.heredocs, self.arith = nesting, start, 0, arith
        self.raw, self.ps, self.escape = raw, powershell, "`" if powershell else "\\"
        self.out: list[str] = []
        self.inner: list[str] = []
        self.docs: list[tuple[str, bool, bool]] = []
        self.quote, self.i, self.closer, self.depth, self.cases = "", start, closer, 0, 0
        self.first_close = -1  # where the first parenthesis this pass opened closed again

    def run(self) -> tuple[str, list[str]]:
        while self.i < len(self.raw) and not self._closes():
            self._step(self.raw[self.i])
        if self.closer and self.i >= len(self.raw):
            raise UnreadableError  # bash refuses an unclosed substitution too
        return "".join(self.out), self.inner

    def _closes(self) -> bool:
        """At the unquoted closer of the substitution or `${...}` this nested pass reads."""
        char = self.raw[self.i]
        if not self.closer or self.quote:
            return False
        if self.closer == ")" and self._word("case"):
            self.cases += 1
        elif self.closer == ")" and self._word("esac", after_in=True):
            self.cases -= 1
        if self.cases > 0:
            return False  # inside case ... esac, a pattern's parentheses are not the substitution's
        if char == "(" and self.closer == ")" and (self.arith or self.raw[self.i + 1 : self.i + 2] != "("):
            self.depth += 1  # outside arithmetic, a `((` is read whole by its own nested pass
        elif char == self.closer:
            self.depth -= 1
            if self.depth == 0 and self.first_close < 0:
                self.first_close = self.i
        return self.depth < 0

    def _word(self, word: str, *, after_in: bool = False) -> bool:
        """`word` as a command at this point: after a separator or a reserved word, not as an argument."""
        at, end = self.i, self.i + len(word)
        if not self.raw.startswith(word, at) or self.raw[end : end + 1].isalnum() or self.raw[end : end + 1] == "_":
            return False
        blank = at
        while blank > self.start and self.raw[blank - 1] in " \t":
            blank -= 1
        # What precedes the blanks, with blank runs collapsed; a bounded window keeps this linear.
        before = re.sub(r"[ \t]+", " ", self.raw[max(self.start, blank - 256) : blank])
        if after_in and _CASE_IN.search(before):
            return True  # `case x in esac` has no patterns at all
        return not before or before[-1] in ";&|\n(" or bool(_COMMAND_WORD.search(before))

    def _word_break(self) -> bool:
        """Whether a word may start here: at the start, or after a metacharacter this pass emitted as one.

        A `#` right after a substitution's `)` continues that word; one after a subshell's `)` starts a comment.
        """
        last = next((piece[-1] for piece in reversed(self.out) if piece), "")
        return not last or last in _WORD_BEFORE

    def _emit(self, text: str, end: int) -> None:
        self.out.append(text)
        self.i = end

    def _step(self, char: str) -> None:
        raw, at, quote = self.raw, self.i, self.quote
        nxt = raw[at + 1 : at + 2]
        if quote == "'":
            self.quote = "" if char == "'" else quote
            self._emit(char, at + 1)
        elif char == self.escape:
            literal = self.ps and not quote and nxt not in ("'", "\n", "")
            self._emit(f"'{nxt}'" if literal else raw[at : at + 2], at + 2)
        elif not quote and self._unquoted(char, nxt):
            return
        elif char == "$":
            self._dollar(nxt)
        elif char == "`" and not self.ps:
            self._backtick(at + 1)
        else:
            if char in "'\"" and quote in ("", char):
                self.quote = "" if quote else char
            self._emit(char, at + 1)

    def _unquoted(self, char: str, nxt: str) -> bool:
        """A comment, a newline ending heredoc lines, a heredoc operator or a process substitution; True if one."""
        raw, at, shell = self.raw, self.i, not self.ps and self.closer != "}" and not self.arith
        if char == "#" and self.closer != "}" and self._word_break():
            end = raw.find("\n", at)
            self._emit(raw[at:end] if end >= 0 else raw[at:], end if end >= 0 else len(raw))
        elif char == "\n":
            self._emit(char, at + 1)
            self._bodies()
        elif shell and (heredoc := _HEREDOC.match(raw, at)):
            self.heredocs += 1
            if self.heredocs > MAX_HEREDOCS:
                raise TooDeepError
            word = heredoc.group(2)
            self.docs.append((_delimiter(word), bool(heredoc.group(1)), not set(word) & set("'\"\\")))
            self._emit(heredoc.group(), heredoc.end())
        elif not self.ps and char in "<>" and nxt == "(":
            self._nested(at + 2, ")")
        elif shell and char == "(" and nxt == "(":
            self._nested(at + 1, ")")  # `(( ... ))`: arithmetic, where `<<` is a shift, not a heredoc
            self.out.append(" ")  # a command ends there: a `#` after it starts a comment
        else:
            return False
        return True

    def _dollar(self, nxt: str) -> None:
        at, unquoted = self.i, not self.quote
        if self.ps and nxt == "{":
            end = at + 2
            while end < len(self.raw) and self.raw[end] != "}":
                end += 2 if self.raw[end] == "`" else 1
            self._emit(EXPANDED, end + 1)  # a PowerShell ${name} ends at the first unescaped brace
        elif nxt in "({" and nxt:
            self._nested(at + 2, ")" if nxt == "(" else "}")
        elif unquoted and not self.ps and nxt == "'":
            end = at + 2
            while end < len(self.raw) and self.raw[end] != "'":
                end += 2 if self.raw[end] == "\\" else 1
            text = _ANSI.sub(_ansi_char, self.raw[at + 2 : end])
            self._emit("'" + text.replace("'", "'\\''") + "'", end + 1)
        elif unquoted and not self.ps and nxt == '"':
            self._emit("", at + 1)  # $"..." is a translated string: the `$` goes, the string stays
        else:
            expands = bool(nxt) and (nxt.isalnum() or nxt in _STARTS)
            self._emit(EXPANDED if expands else "$", at + 1)

    def _nested(self, start: int, closer: str) -> None:
        """Replace `$(...)`, `<(...)`, `((...))` or `${...}` with EXPANDED; a substitution's script is judged alone.

        Text opening with `(` is arithmetic (`$((...))`, `((...))`): its substitutions are judged, the rest is not a
        script. A heredoc the nested text opens but does not finish keeps its body on the lines that follow.
        """
        nested = _Marker(self.raw, powershell=self.ps, start=start, closer=closer, nesting=self.nesting + 1)
        nested.run()
        # Arithmetic only when its `(` closes as `))`; `((cd x); ls)` is a subshell, `$((cd x); ls)` a substitution.
        arith = nested.arith and nested.first_close == nested.i - 1  # the opening `(` closes right into `))`
        script = closer == ")" and not arith
        self.inner += ([self.raw[start : nested.i]] if script else []) + nested.inner
        self.docs = nested.docs + self.docs  # bash reads a substitution's heredoc bodies before the enclosing ones
        self._emit(EXPANDED, nested.i + 1)

    def _backtick(self, start: int) -> None:
        end = start
        while end < len(self.raw) and self.raw[end] != "`":
            end += 2 if self.raw[end] == "\\" else 1
        escape = _BACKTICK_ESCAPE_QUOTED if self.quote == '"' else _BACKTICK_ESCAPE
        self.inner.append(escape.sub(r"\1", self.raw[start:end]))  # bash drops these backslashes first
        self._emit(EXPANDED, end + 1)

    def _bodies(self) -> None:
        """Copy the pending heredoc bodies through to their delimiter lines, quotes and all."""
        while self.docs:
            delimiter, strip, expands = self.docs.pop(0)
            start = end = self.i
            while end < len(self.raw):
                stop = self.raw.find("\n", end)
                stop = len(self.raw) if stop < 0 else stop + 1
                line = self.raw[end:stop].rstrip("\n")  # bash keeps a carriage return: `EOF\r` is not EOF
                end = stop
                if (line.lstrip("\t") if strip else line) == delimiter:
                    break
            if expands:
                self._body_scripts(self.raw[start:end])
            # A body holds no names; blank its quotes so the parser, which may end a body elsewhere, keeps step.
            self._emit(self.raw[start:end].translate(_BODY_QUOTES), end)

    def _body_scripts(self, body: str) -> None:
        """An unquoted heredoc body runs its `$(...)` and backtick commands: judge their scripts too."""
        reader = _Marker(body, powershell=False, nesting=self.nesting + 1)
        while reader.i < len(body):
            char = body[reader.i]
            if char == "\\":
                reader.i += 2
            elif body.startswith("$(", reader.i):
                reader._dollar("(")
            elif char == "`":
                reader._backtick(reader.i + 1)
            else:
                reader.i += 1
        self.inner += reader.inner


def mark_expansions(raw: str, *, powershell: bool) -> tuple[str, list[str]]:
    """The command line with expansions marked, and the inner scripts of its command substitutions."""
    return _Marker(raw, powershell=powershell).run()
