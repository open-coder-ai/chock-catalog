"""dockerfile-compose-security: heredoc openers read as BuildKit 0.33 reads them.

Expected names were recorded by running moby/buildkit v0.33.1 `frontend/dockerfile/parser.Parse` on
`RUN <line>` with the terminators below it; an empty list is a line that opens none (or that BuildKit
refuses to parse, so the image never builds).
"""

from __future__ import annotations

import pytest
from policies import dockerkit

dockerkit.load()

from dkscan import heredoc  # noqa: E402

BUILDKIT = [
    ("cat <<EOF", ["EOF"]),
    ("cat << EOF > /etc/motd", ["EOF"]),
    ("cat <<\\EOF > /etc/motd", ["EOF"]),
    ("cat <<.EOF", [".EOF"]),
    ("cat <<1EOF", ["1EOF"]),
    ("cat <<EOF>/etc/motd", ["EOF>/etc/motd"]),
    ('cat <<E"OF"', ["EOF"]),
    ("cat <<EOF)", ["EOF)"]),
    ('echo "x" <<EOF', ["EOF"]),
    ("echo $(( <<EOF", ["EOF"]),
    ("echo $((1<<BITS))", []),
    ("echo $(( 2 <<SHIFT ))", ["SHIFT"]),
    ('echo "x<<EOF"', []),
    ("echo 'a<<B'", []),
    ("a=b<<C", []),
    ("cat 3<<'A' <<-B", ["A", "B"]),
    ("cat <<-EOF", ["EOF"]),
    ("cat <<'EOF'", ["EOF"]),
    ('cat <<"EOF"', ["EOF"]),
    ("cat <<EOF;true", ["EOF;true"]),
    ("cat <<<word", []),
    ("cat <<  \tEOF", ["EOF"]),
    ("python3 <<PY", ["PY"]),
    ("cat <<EOF <<EOF2", ["EOF", "EOF2"]),
    ("cat <<${X}", ["${X}"]),
    ("cat <<$X", ["$X"]),
    ("cat <<${X:-a b}", []),
    ("echo ${X", []),
    ("echo 'open <<EOF", []),
    ("cat <<EOF # c", ["EOF"]),
    ("cat <<a-b", ["a-b"]),
    ("cat <<a.b", ["a.b"]),
    ("x<<EOF", []),
    ("cat <<\\\\EOF", ["\\EOF"]),
    ("cat <<E\\OF", ["EOF"]),
    ("cat < <EOF", []),
    ("cat <<'E O F'", ["E O F"]),
    ('cat <<"$Y"', ["$Y"]),
    ("cat <<-'EOF'", ["EOF"]),
    ("cat 10<<EOF", ["EOF"]),
    ("cat <<${A/b/c}", []),
    ("cat <<${A:#x}", []),
    ("cat <<${A:x}", []),
    ("echo ${}", []),
    ("cat <<E'O'F", ["EOF"]),
    ("cat <<''", []),
    ('cat <<""', []),
    ("cat <<a ", ["a"]),
    ('echo "abc <<A', []),
    ("echo $1 <<A", ["A"]),
    ("echo $$ <<A", ["A"]),
    ("echo ${} <<A", []),
    ("echo ${A <<A", []),
    ("cat <<${A:-x", []),
    ("echo ${A} <<B", ["B"]),
    ("cat <<$1", ["$1"]),
    ("cat <<a\\ b", ["a b"]),
    ('echo "a\\"b" <<A', ["A"]),
    ('echo "$X" <<A', ["A"]),
    ("echo ${A:", []),
    ("echo ${A?x} <<B", ["B"]),
    ("echo ${A%x} <<B", ["B"]),
    ("echo ${A:%x} <<B", []),
    ("echo ${A=x} <<B", []),
]


@pytest.mark.parametrize(("line", "names"), BUILDKIT)
def test_openers_match_buildkit(line: str, names: list[str]) -> None:
    assert [name for _, name in heredoc.openers("RUN " + line)] == names


def test_dash_opener_strips_tabs() -> None:
    assert heredoc.openers("RUN cat <<-EOF <<B") == [(True, "EOF"), (False, "B")]
    assert heredoc.openers("RUN true") == []


def test_lexer_edges() -> None:
    assert heredoc.openers("RUN  cat  <<A") == [(False, "A")]
    assert heredoc.openers("RUN cat <<A \\") == [(False, "A")]
    assert heredoc.openers("RUN cat <<B ${A") == []
