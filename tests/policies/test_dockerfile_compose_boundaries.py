"""dockerfile-compose-security: instruction boundaries (continuations, heredocs) as BuildKit 0.33 draws them.

Each expected list of start lines was recorded by running moby/buildkit v0.33.1 parser.Parse (and
instructions.Parse, which accepted every file) on the text.
"""

from __future__ import annotations

import pytest
from policies import dockerkit

dockerkit.load()

from dkscan import dockerfile  # noqa: E402

BUILDKIT = [
    ("FROM a\nRUN x \\\\\nRUN y \\  \nUSER root\nRUN cat <\\\nRUN cat <\\\n", [1, 2, 3, 5]),
    ("FROM a\nRUN y \\  \nB\n# comment\n", [1, 2]),
    ("FROM a\nRUN echo a \\\nhello\nRUN x \\\\\nRUN ch\\\n\tEOF\n\nRUN ch\\\n  \\\n", [1, 2, 4, 5, 8]),
    ("FROM a\nRUN cat <\\\nhello\nRUN 'a<<EOF'\n", [1, 2, 4]),
    ("FROM a\nRUN cat <<EOF\nmod 1\nRUN <<A <<B\nB\n  \\\nRUN cat <\\\nEOF\nUSER root\n", [1, 2, 9]),
    ("FROM a\nRUN ch\\\n\n  b\nRUN y \\  \nRUN y \\  \nUSER 1000\n", [1, 2, 5]),
    ("FROM a\n# comment\nRUN ch\\\n# comment\n\nUSER 1000\nRUN 'a<<EOF'\n", [1, 3, 7]),
    ("FROM a\n\nUSER 1000\nRUN ch\\\nEOF\n", [1, 3, 4]),
    ("FROM a\nCOPY <<EOF /x\nEOF\nRUN x \\\\\n", [1, 2, 4]),
    (
        "FROM a\nRUN ch\\\nRUN y \\  \n  b\nUSER root\nRUN 'a<<EOF'\n  \\\nRUN echo a \\\nRUN cat <\\\nRUN 'a<<EOF'\n",
        [1, 2, 5, 6, 7],
    ),
    ("FROM a\nRUN y \\  \nRUN echo a \\\nUSER 1000\nRUN cat <\\\n# comment\nA\n", [1, 2, 5]),
    ("FROM a\nRUN echo a \\\n# comment\nRUN y \\  \n  b\n", [1, 2]),
    (
        "FROM a\nUSER 1000\nRUN x \\\\\nUSER 1000\nRUN cat <<\\\n<EOF\nRUN y \\  \nUSER 1000\nRUN cat <\\\nB\n",
        [1, 2, 3, 4, 5, 7, 9],
    ),
    ("FROM a\nRUN ch\\\nUSER 1000\nRUN 'a<<EOF'\n", [1, 2, 4]),
    ("FROM a\nUSER 1000\n\nRUN ch\\\nRUN echo a \\\n", [1, 2, 4]),
    ("FROM a\nUSER 1000\n\nRUN cat <\\\nRUN y \\  \n", [1, 2, 4]),
    ("FROM a\nRUN x \\\\\nRUN y \\  \nRUN cat <\\\n  b\n", [1, 2, 3]),
    ("FROM a\nRUN cat <\\\n  \\\n\tEOF\nRUN 'a<<EOF'\nRUN ch\\\nA\n", [1, 2, 5, 6]),
    (
        "FROM a\nRUN 'a<<EOF'\nRUN y \\  \nRUN cat <\\\n\tEOF\nRUN x \\\\\nRUN y \\  \n# comment\n  \\\nUSER 1000\n",
        [1, 2, 3, 6, 7],
    ),
    ("FROM a\n\nUSER 1000\n\n\nRUN cat <\\\nUSER 1000\nRUN x \\\\\n# comment\nUSER root\n", [1, 3, 6, 8, 10]),
    ("FROM a\nRUN 'a<<EOF'\nRUN cat <<EOF\nA\nEOF\nRUN ch\\\n", [1, 2, 3, 6]),
    ("FROM a\nRUN cat <\\\nUSER 1000\nRUN cat <<-EOF\n# comment\nRUN ch\\\nB\nRUN echo a \\\n\n\tEOF\n", [1, 2, 4]),
    ("FROM a\n\nRUN ch\\\nRUN 'a<<EOF'\nRUN x \\\\\n", [1, 3, 5]),
    ("FROM a\n\nRUN x \\\\\nUSER root\n", [1, 3, 4]),
    (
        "FROM a\nRUN x \\\\\nRUN echo a \\\nRUN y \\  \n\tEOF\nRUN ch\\\nRUN ch\\\n<EOF\nRUN echo a \\\n",
        [1, 2, 3, 6, 9],
    ),
    ("FROM a\nRUN cat <\\\nRUN x \\\\\n\nUSER 1000\nRUN cat <<\\\n  \\\n", [1, 2, 5, 6]),
    ("FROM a\nRUN cat <<-EOF\nA\n  b\nRUN cat <\\\n  \\\n# comment\nRUN cat << EOF \\\nEOF\n", [1, 2]),
    ("FROM a\nRUN y \\  \nCOPY <<EOF /x\nUSER root\nRUN x \\\\\nEOF\n", [1, 2]),
    ("FROM a\nRUN cat <\\\nEOF\n\nRUN ch\\\n", [1, 2, 5]),
    ("FROM a\nRUN y \\  \nmod 1\nRUN cat <\\\n\tEOF\nRUN echo a \\\n", [1, 2, 4, 6]),
    ("FROM a\nRUN ch\\\nRUN y \\  \nRUN 'a<<EOF'\nRUN echo a \\\nUSER 1000\nUSER root\n", [1, 2, 5, 7]),
    ("FROM a\nRUN y \\  \nRUN y \\  \nA\n", [1, 2]),
    ("FROM a\n  \\\nRUN ch\\\n<EOF\n", [1, 2]),
    ("FROM a\nRUN cat << EOF \\\nEOF\nhello\nEOF\nRUN echo a \\\nEOF\n", [1, 2, 6]),
    ("FROM a\nRUN cat <\\\nRUN ch\\\n  \\\n  b\nUSER 1000\n", [1, 2, 6]),
    ("FROM a\n\nRUN y \\  \nUSER root\nRUN x \\\\\n", [1, 3, 5]),
    ("FROM a\nRUN cat <\\\nRUN cat << EOF \\\nRUN echo a \\\nUSER root\nRUN cat <<-EOF\nEOF\nUSER 1000\n", [1, 2, 8]),
    ("FROM a\n# comment\nRUN echo a \\\nRUN cat <\\\n", [1, 3]),
    (
        "FROM a\nCOPY <<EOF /x\nRUN cat <<EOF\nRUN <<A <<B\nUSER root\nRUN echo a \\\nRUN cat <<EOF\nRUN cat << EOF \\\nEOF\n",
        [1, 2],
    ),
    ("FROM a\nRUN cat <\\\n  \\\n\n", [1, 2]),
]


@pytest.mark.parametrize(("text", "starts"), BUILDKIT)
def test_instruction_starts_match_buildkit(text: str, starts: list[int]) -> None:
    assert [instr.line for instr in dockerfile.parse(text)] == starts
