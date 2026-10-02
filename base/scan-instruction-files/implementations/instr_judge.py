"""Judge an instruction file's statements against the lexicon in one pass per pattern: phrase rules with a
prohibition discount, the exfiltration combinations, fake trust blocks that carry commands, and the
statements that state a guardrail. Each pattern runs once over the statements joined by newlines, and a
match is mapped back to its statement by offset, so a file costs a fixed number of passes."""

from __future__ import annotations

import bisect
import re
from collections import defaultdict

from instr_rules import BLOCK, Hit, Lexicon
from instr_text import Statement

#: How far back a negation may sit and still govern a match ("never ... run X"): one clause, at most this many characters.
LOOKBACK = 240
#: How many words before a match a negation may sit and still govern it.
GOVERN_WORDS = 8
#: The compact rule form never(context): X, which governs X when X is at most two words on.
COMPACT = re.compile(r"\b(?:never|not|no)\s*\([^()]{0,120}\)\s*:?\s*(?:\S+\s+){0,2}$")
#: Nothing before a `)` or a `:` governs what follows it.
CUT = re.compile(r"[):]")
#: How many statements after a fake trust tag its block may run when no closing tag ends it sooner.
TRUST_SPAN = 12
COMMAND_RULES = frozenset({"fetch-exec", "decode-exec", "exfil-secret"})
EXFIL = ("exfil-secret", BLOCK, "tells the agent to send a secret to a remote destination")
TRUST = ("fake-trust-exec", BLOCK, "a fake trust block that runs a command")
#: A guarded topic's word reduced to its stem, so review/reviewer/reviews or test/tests/testing are one topic.
STEM = re.compile(r"(?:s|es|ed|er|ers|ing)$")
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
        self.segment_ends = [m.end() for m in self.p["segment_break"].finditer(self.text)]

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

    def clause_start(self, pos: int) -> int:
        """Where the clause holding `pos` starts: a clause break, the statement's start, or LOOKBACK back."""
        k = bisect.bisect_right(self.break_ends, pos) - 1
        return max(self.starts[self.index(pos)], self.break_ends[k] if k >= 0 else 0, pos - LOOKBACK)

    def clause_end(self, pos: int) -> int:
        """Where the clause holding `pos` ends: the next clause break, the statement's end, or 2 * LOOKBACK on."""
        k = bisect.bisect_left(self.break_starts, pos)
        end = min(self.ends[self.index(pos)], self.break_starts[k] if k < len(self.break_starts) else len(self.text))
        return min(end, pos + 2 * LOOKBACK)

    def governs(self, low: int, pos: int) -> bool:
        """True when a negation between `low` and `pos` governs what starts at `pos`: one of the GOVERN_WORDS
        words just before it, with no `)` or `:` in between ("never run X"), or the compact form
        never(context): X with X at most two words on."""
        before = self.text[low:pos]
        if COMPACT.search(before):
            return True
        tail = self.p["encourager"].sub(" ", CUT.split(before)[-1]).split()
        return self.p["negation"].search(" ".join(tail[-GOVERN_WORDS:])) is not None

    def prohibited(self, pos: int) -> bool:
        """True when a negation earlier in the same clause governs what starts at `pos` ("never run X")."""
        return self.governs(self.clause_start(pos), pos)

    def rule_hits(self) -> dict[int, list[Hit]]:
        out: dict[int, list[Hit]] = defaultdict(list)
        for rule in self.lex.rules:
            targets = [m.start() for _, m in self.matches(rule.target)] if rule.target is not None else None
            fired: set[int] = set()
            for i, m in self.matches(rule.phrase):
                if i in fired:
                    continue
                if targets is not None and not self._live_target(
                    targets, m.end(), *self._target_span(rule.target_scope, i, m)
                ):
                    continue
                if not (rule.discount and self.prohibited(m.start())):
                    fired.add(i)
                    out[i].append(Hit(rule.id, rule.verdict, rule.label, self.sts[i]))
        return out

    def _live_target(self, targets: list[int], after: int, low: int, high: int) -> bool:
        """A target between `low` and `high` that no negation after the phrase (ending at `after`) governs:
        in "without asking, never push" the push is not a risky target."""
        k = bisect.bisect_left(targets, low)
        while k < len(targets) and targets[k] < high:
            if targets[k] < after or not self.governs(max(after, self.clause_start(targets[k])), targets[k]):
                return True
            k += 1
        return False

    def _target_span(self, scope: str, i: int, m: re.Match[str]) -> tuple[int, int]:
        """Where a rule's target may sit: its statement, or the segment (between sentence ends and semicolons)
        holding the phrase."""
        if scope == "statement":
            return self.starts[i], self.ends[i]
        k = bisect.bisect_right(self.segment_ends, m.start())
        low = max(self.starts[i], self.segment_ends[k - 1] if k else 0)
        high = min(self.ends[i], self.segment_ends[k] if k < len(self.segment_ends) else self.ends[i])
        return low, high

    def exfil(self) -> set[int]:
        """Statements that send a secret somewhere: prose ("upload ~/.ssh/id_rsa to https://..."), a shell
        line that feeds a secret into a network tool (pipe, data flag, substitution), or DNS-shaped exfil."""
        p = self.p
        found = {i for i, m in self.matches(p["dns_exfil"]) if not self.prohibited(m.start())}
        nets: dict[int, list[int]] = defaultdict(list)
        for i, m in self.matches(p["net_tool"]):
            nets[i].append(m.start())
        for i in nets.keys() & self.statements_with(p["secret_strong"]):
            # A header value holding a plain variable is how an API is called, not what is sent.
            line = p["header_arg"].sub(" ", self.sts[i].norm)
            if not (p["secret_strong"].search(line) and p["shell_carrier"].search(line)):
                continue
            if self.sts[i].code or any(not self.prohibited(pos) for pos in nets[i]):
                found.add(i)
        at = {k: [m.start() for _, m in self.matches(p[k])] for k in ("destination", "secret_strong")}
        verbs = [(i, m, True) for i, m in self.matches(p["send_verb"])]
        verbs += [(i, m, False) for i, m in self.matches(p["send_weak"])]
        for i, verb, strong_verb in verbs:
            if i not in found and self._sends_secret(verb, at, strong_verb=strong_verb):
                found.add(i)
        return found

    def _sends_secret(self, verb: re.Match[str], at: dict[str, list[int]], *, strong_verb: bool) -> bool:
        """The verb's object is a secret, sent to a destination: a secret file, env dump or secret variable
        before the destination (or after it, for a plain send verb), or for a plain send verb a credential that
        is its direct object ("post the API key to ..."), unless the clause is about an auth header. A weak
        verb (push, copy, share) counts only with a secret file or variable as its object. A negation that
        governs the verb, or the secret after it, discounts it."""
        start, end = verb.end(), self.clause_end(verb.end())
        i = self.index(start)
        dest = _first(at["destination"], start, end)
        if dest is None and not _within(at["destination"], self.starts[i], self.ends[i]):
            return False
        object_end = end if dest is None else dest
        secret = _first(at["secret_strong"], start, object_end)
        if secret is None and strong_verb and dest is not None:
            secret = _first(at["secret_strong"], dest, end)
        if secret is not None:
            return not self.prohibited(verb.start()) and not self.governs(start, secret)
        if not strong_verb or self.p["auth_context"].search(self.text, start, end):
            return False
        return self.p["secret_object"].match(self.text, start, object_end) is not None and not self.prohibited(
            verb.start()
        )

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


def _first(starts: list[int], low: int, high: int) -> int | None:
    """The first match start at or after `low` and before `high`, else None."""
    k = bisect.bisect_left(starts, low)
    return starts[k] if k < len(starts) and starts[k] < high else None


def _within(starts: list[int], low: int, high: int) -> bool:
    return _first(starts, low, high) is not None


def judge(lex: Lexicon, sts: list[Statement]) -> list[Hit]:
    """Every rule that fires on the file's statements: per statement each rule at most once, refusals first."""
    doc = Doc(lex, sts)
    hits = doc.rule_hits()
    for i in doc.exfil():
        hits[i].insert(0, Hit(*EXFIL, sts[i]))
    found = [hit for i in sorted(hits) for hit in sorted(hits[i], key=lambda h: h.verdict != BLOCK)]
    return found + doc.trust_blocks(hits)


def guardrails(lex: Lexicon, sts: list[Statement]) -> dict[int, frozenset[str]]:
    """The statements that state a guardrail (a mandate word and a guarded topic), each with its topics, each
    topic marked by the statement's polarity (a prohibition, or a positive mandate)."""
    doc = Doc(lex, sts)
    mandates = doc.statements_with(lex.p["guard_mandate"])
    prohibitions = doc.statements_with(lex.p["guard_prohibit"])
    topics: dict[int, set[str]] = defaultdict(set)
    for i, m in doc.matches(lex.p["guard_topic"]):
        if i in mandates:
            topics[i].add(("never " if i in prohibitions else "always ") + (STEM.sub("", m.group()) or m.group()))
    return {i: frozenset(found) for i, found in topics.items()}
