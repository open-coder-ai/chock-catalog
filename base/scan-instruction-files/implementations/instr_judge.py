"""Judge an instruction file's statements against the lexicon in one pass per pattern: phrase rules with a
prohibition discount, the exfiltration combinations, fake trust blocks that carry commands, and the
statements that state a guardrail. Each pattern runs once over the statements joined by newlines, and a
match is mapped back to its statement by offset, so a file costs a fixed number of passes."""

from __future__ import annotations

import bisect
import re
from collections import Counter, defaultdict

from instr_rules import BLOCK, Hit, Lexicon
from instr_text import Statement

#: How far back a negation may sit and still govern a match ("never ... run X"): one clause, at most this many characters.
LOOKBACK = 240
#: How many words after a send verb a generic secret noun ("the credentials") still counts as its object.
OBJECT_WORDS = 8
#: How many statements after a fake trust tag its block may run when no closing tag ends it sooner.
TRUST_SPAN = 12
COMMAND_RULES = frozenset({"fetch-exec", "decode-exec", "exfil-secret"})
EXFIL = ("exfil-secret", BLOCK, "tells the agent to send a secret to a remote destination")
TRUST = ("fake-trust-exec", BLOCK, "a fake trust block that runs a command")
CLOSING_TAG = re.compile(r"[<\[]{1,2}\s*/|<\|\s*im_end")


class Doc:
    """One file's statements, joined, with the offsets and clause breaks every rule shares."""

    def __init__(self, lex: Lexicon, sts: list[Statement]) -> None:
        self.lex, self.sts, self.p = lex, sts, lex.p
        self.starts, self.ends, pos = [], [], 0
        for st in sts:
            self.starts.append(pos)
            self.ends.append(pos + len(st.norm))
            pos += len(st.norm) + 1
        self.text = "\n".join(st.norm for st in sts)
        found = list(self.p["clause_break"].finditer(self.text))
        self.break_starts = [m.start() for m in found]
        self.break_ends = [m.end() for m in found]

    def index(self, pos: int) -> int:
        return bisect.bisect_right(self.starts, pos) - 1

    def matches(self, pattern: re.Pattern[str]) -> list[tuple[int, re.Match[str]]]:
        """(statement, match) for every match, each kept inside one statement: a match that runs on into
        the next statement is searched for again within its own."""
        out, pos, text = [], 0, self.text
        while (m := pattern.search(text, pos)) is not None:
            i = self.index(m.start())
            if m.end() > self.ends[i]:
                m = pattern.search(text, m.start(), self.ends[i])
                if m is None:
                    pos = self.ends[i] + 1
                    continue
            out.append((i, m))
            pos = max(m.end(), m.start() + 1)
        return out

    def statements_with(self, pattern: re.Pattern[str]) -> set[int]:
        return {i for i, _ in self.matches(pattern)}

    def prohibited(self, pos: int) -> bool:
        """True when a negation earlier in the same clause governs what starts at `pos` ("never run X")."""
        k = bisect.bisect_right(self.break_ends, pos) - 1
        start = max(self.starts[self.index(pos)], self.break_ends[k] if k >= 0 else 0, pos - LOOKBACK)
        clause = self.p["encourager"].sub(" ", self.text[start:pos])
        return self.p["negation"].search(clause) is not None

    def clause_after(self, pos: int) -> str:
        k = bisect.bisect_left(self.break_starts, pos)
        end = min(self.ends[self.index(pos)], self.break_starts[k] if k < len(self.break_starts) else len(self.text))
        return self.text[pos : min(end, pos + 2 * LOOKBACK)]

    def rule_hits(self) -> dict[int, list[Hit]]:
        out: dict[int, list[Hit]] = defaultdict(list)
        for rule in self.lex.rules:
            targets = self.statements_with(rule.target) if rule.target is not None else None
            fired: set[int] = set()
            for i, m in self.matches(rule.phrase):
                if i in fired or (targets is not None and i not in targets):
                    continue
                if not (rule.discount and self.prohibited(m.start())):
                    fired.add(i)
                    out[i].append(Hit(rule.id, rule.verdict, rule.label, self.sts[i]))
        return out

    def exfil(self) -> set[int]:
        """Statements that send a secret somewhere: prose ("upload ~/.ssh/id_rsa to https://..."), a shell
        line that feeds a secret into a network tool (pipe, data flag, substitution), or DNS-shaped exfil."""
        p = self.p
        found = {i for i, m in self.matches(p["dns_exfil"]) if not self.prohibited(m.start())}
        nets: dict[int, list[int]] = defaultdict(list)
        for i, m in self.matches(p["net_tool"]):
            nets[i].append(m.start())
        strong, carriers = self.statements_with(p["secret_strong"]), self.statements_with(p["shell_carrier"])
        for i in nets.keys() & strong & carriers:
            if self.sts[i].code or any(not self.prohibited(pos) for pos in nets[i]):
                found.add(i)
        destinations = self.statements_with(p["destination"])
        strong_at = [m.start() for _, m in self.matches(p["secret_strong"])]
        generic_at = [m.start() for _, m in self.matches(p["secret_generic"])]
        for i, verb in self.matches(p["send_verb"]):
            if i in found or i not in destinations:
                continue
            end = verb.end() + len(self.clause_after(verb.end()))
            window = self._words_end(verb.end(), end)
            if (_within(strong_at, verb.end(), end) or _within(generic_at, verb.end(), window)) and not self.prohibited(
                verb.start()
            ):
                found.add(i)
        return found

    def _words_end(self, pos: int, end: int) -> int:
        """Where the first OBJECT_WORDS words after `pos` end, within `end`."""
        for _ in range(OBJECT_WORDS + 1):
            nxt = self.text.find(" ", pos + 1, end)
            if nxt < 0:
                return end
            pos = nxt
        return pos

    def trust_blocks(self, hits: dict[int, list[Hit]]) -> list[Hit]:
        """A fake trust tag that opens a block (<system>, [INST]) whose body -- to its closing tag, at most
        TRUST_SPAN statements -- runs a command."""
        rule = next(r for r in self.lex.rules if r.id == "fake-trust")
        commands = self.statements_with(self.p["net_tool"]) | {
            i for i, found in hits.items() if any(h.rule in COMMAND_RULES for h in found)
        }
        closes = self.statements_with(self.p["fake_trust_close"])
        out, opened = [], set()
        for i, m in self.matches(rule.phrase):
            if i in opened or m.group()[0] not in "<[" or CLOSING_TAG.match(m.group()) or self.prohibited(m.start()):
                continue
            opened.add(i)
            last = i
            if not self.p["fake_trust_close"].search(self.text, m.end(), self.ends[i]):
                for j in range(i + 1, min(i + TRUST_SPAN, len(self.sts))):
                    last = j
                    if j in closes:
                        break
            if commands & set(range(i, last + 1)):
                span = self.sts[i : last + 1]
                region = Statement(
                    span[0].first,
                    span[-1].last,
                    " ".join(s.raw for s in span),
                    " ".join(s.norm for s in span),
                    code=False,
                )
                out.append(Hit(*TRUST, region))
        return out


def _within(starts: list[int], low: int, high: int) -> bool:
    """True when a match starts at or after `low` and before `high`."""
    k = bisect.bisect_left(starts, low)
    return k < len(starts) and starts[k] < high


def judge(lex: Lexicon, sts: list[Statement]) -> list[Hit]:
    """Every rule that fires on the file's statements: per statement each rule at most once, refusals first."""
    doc = Doc(lex, sts)
    hits = doc.rule_hits()
    for i in doc.exfil():
        hits[i].insert(0, Hit(*EXFIL, sts[i]))
    found = [hit for i in sorted(hits) for hit in sorted(hits[i], key=lambda h: h.verdict != BLOCK)]
    return found + doc.trust_blocks(hits)


def guardrails(lex: Lexicon, sts: list[Statement]) -> Counter[str]:
    """Normalized statements that state a guardrail: a mandate word and a guarded topic."""
    doc = Doc(lex, sts)
    both = doc.statements_with(lex.p["guard_mandate"]) & doc.statements_with(lex.p["guard_topic"])
    return Counter(sts[i].norm for i in both)
