"""Judge an instruction file's statements against the lexicon in one pass per pattern: phrase rules with a
prohibition discount, the exfiltration combinations, fake trust blocks that carry commands, and the
statements that state a guardrail. Each pattern runs once over the statements joined by newlines, and a
match is mapped back to its statement by offset, so a file costs a fixed number of passes."""

from __future__ import annotations

import bisect
import re
from collections import defaultdict

from instr_rules import ASK, BLOCK, Hit, Lexicon
from instr_text import Statement

#: How far back a negation may sit and still govern a match ("never ... run X"): one clause, at most this many characters.
LOOKBACK = 240
#: How many words before a match a negation may sit and still govern it: for an ask, for a refusal (the
#: negation must sit right before the verb: never send, do not upload), and for a risky target.
GOVERN_WORDS = 8
TIGHT_WORDS = 2
TARGET_WORDS = 4
#: The compact rule form never(context): X, which governs X when X is at most two words on.
COMPACT = re.compile(r"\bnever\s*\([^()]{0,120}\)\s*:\s*(?:\S+\s+){0,2}$")
#: What ends a negation's reach: a closing bracket or `>`, colon, semicolon, pipe, arrow (->, =>, \u2192), a spaced
#: dash or double dash, a closing double quote, and/then/so. A comma ends it too, unless what follows continues a list ending in or/nor.
CUT = re.compile(r"[)\]:;|>\u2192\u21d2\u27f6]|\s--?\s|\b(?:and|then|so)\b")
#: A colon or dash that joins a send verb to its destination when "to" (into, at, onto, via) sits beside it.
JOINER = re.compile(r"\s*(?::|-{1,2})")
TO_WORD = re.compile(r"\b(?:to|into|at|onto|via)\b")
LIST_OR = re.compile(r"\b(?:or|nor)\b")
#: How many statements after a fake trust tag its block may run when no closing tag ends it sooner.
TRUST_SPAN = 12
COMMAND_RULES = frozenset({"fetch-exec", "decode-exec", "exfil-secret"})
EXFIL = ("exfil-secret", BLOCK, "tells the agent to send a secret to a remote destination")
IN_REQUEST = ("secret-in-request", ASK, "puts a secret variable in a URL or form field a network tool sends")
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
        self._dead: dict[int, bool] = {}

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

    def _object_end(self, pos: int) -> int:
        """Where a send verb's clause ends, carried past a colon or dash that joins it to its destination
        ("to: https://...", "-- to https://...")."""
        end, limit = self.clause_end(pos), min(self.ends[self.index(pos)], pos + 2 * LOOKBACK)
        while end < limit and JOINER.match(self.text, end) and TO_WORD.search(self.text, max(pos, end - 8), end + 8):
            end = max(end + 1, self.clause_end(end + 1))
        return min(end, limit)

    def governs(self, low: int, pos: int, words: int = GOVERN_WORDS) -> bool:
        """True when a negation between `low` and `pos` governs what starts at `pos`: within the `words` words
        just before it and not cut off by a bracket, colon, semicolon, pipe, dash, arrow, and/then/so, or a
        comma (one that continues a list ending in "or" does not cut); or the compact form never(context): X
        with X at most two words on. Encouragers (do not hesitate to, no exceptions) are not negations."""
        before = self.text[low:pos]
        if COMPACT.search(before):
            return True
        reach = CUT.split(before)[-1]
        quotes = reach.count('"')
        if quotes and quotes % 2 == 0:
            reach = reach.rsplit('"', 1)[1]
        parts = reach.split(",")
        reach = parts.pop()
        while parts and LIST_OR.search(reach):
            reach = parts.pop() + "," + reach
        found = self.p["encourager"].sub(" ", reach).split()
        return self.p["negation"].search(" ".join(found[-words:])) is not None

    def prohibited(self, pos: int, words: int = GOVERN_WORDS) -> bool:
        """True when a negation earlier in the same clause governs what starts at `pos` ("never run X")."""
        return self.governs(self.clause_start(pos), pos, words)

    def dead(self, pos: int) -> bool:
        """A risky target its own negation governs ("never push"), remembered per position."""
        if pos not in self._dead:
            self._dead[pos] = self.prohibited(pos, TARGET_WORDS)
        return self._dead[pos]

    def rule_hits(self) -> dict[int, list[Hit]]:
        out: dict[int, list[Hit]] = defaultdict(list)
        for rule in self.lex.rules:
            targets = [m.start() for _, m in self.matches(rule.target)] if rule.target is not None else None
            fired: set[int] = set()
            for i, m in self.matches(rule.phrase):
                if i in fired:
                    continue
                if (
                    targets is not None
                    and self.sts[i].whole
                    and not self._live_target(targets, *self._target_span(rule.target_scope, i, m))
                ):
                    continue
                words = TIGHT_WORDS if rule.verdict == BLOCK else GOVERN_WORDS
                if not (rule.discount and self.prohibited(m.start(), words)):
                    fired.add(i)
                    out[i].append(Hit(rule.id, rule.verdict, rule.label, self.sts[i]))
        return out

    def _live_target(self, targets: list[int], low: int, high: int) -> bool:
        """A target between `low` and `high` that no negation governs: in "without asking, never push" the push
        is not a risky target."""
        k = bisect.bisect_left(targets, low)
        while k < len(targets) and targets[k] < high:
            if not self.dead(targets[k]):
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

    def exfil(self) -> tuple[set[int], set[int]]:
        """(refused, asked): statements that send a secret somewhere -- prose ("upload ~/.ssh/id_rsa to
        https://..."), a network tool fed a secret by a pipe, data flag, redirect or substitution on its own
        command, DNS-shaped exfil -- and statements whose network tool only carries a secret variable inside
        a URL (some APIs authenticate that way, so a person looks). A header or user value holding only a
        plain variable is how an API is called and is set aside."""
        p = self.p
        found = {i for i, m in self.matches(p["dns_exfil"]) if not self.prohibited(m.start(), TIGHT_WORDS)}
        asked: set[int] = set()
        nets: dict[int, list[int]] = defaultdict(list)
        for i, m in self.matches(p["net_tool"]):
            nets[i].append(m.start())
        for i in nets.keys() & self.statements_with(p["secret_strong"]):
            if not (self.sts[i].code or any(not self.prohibited(pos, TIGHT_WORDS) for pos in nets[i])):
                continue
            line = p["header_arg"].sub(" ", self.sts[i].norm)
            bare = p["field_arg"].sub(" ", p["url_arg"].sub(" ", line))
            if p["secret_strong"].search(bare) and p["shell_carrier"].search(line):
                found.add(i)
            elif any(
                p["secret_strong"].search(m.group()) for k in ("url_arg", "field_arg") for m in p[k].finditer(line)
            ):
                asked.add(i)
        set_aside = sorted((m.start(), m.end()) for k in ("header_arg", "field_arg") for _, m in self.matches(p[k]))
        at = {
            "destination": [m.start() for _, m in self.matches(p["destination"])],
            "secret_strong": [
                m.start() for _, m in self.matches(p["secret_strong"]) if not _inside(m.start(), set_aside)
            ],
        }
        verbs = [(i, m, True) for i, m in self.matches(p["send_verb"])]
        verbs += [(i, m, False) for i, m in self.matches(p["send_weak"])]
        for i, verb, strong_verb in verbs:
            if i not in found and self._sends_secret(verb, at, strong_verb=strong_verb):
                found.add(i)
        return found, asked - found

    def _sends_secret(self, verb: re.Match[str], at: dict[str, list[int]], *, strong_verb: bool) -> bool:
        """The verb's object, before the destination, is a secret: a secret file, env dump or secret variable,
        or for a plain send verb a credential that is its direct object ("post the API key to ...") in a clause
        not about an auth header. A weak verb (push, share, report) counts only with a secret file or variable.
        A secret named only after the destination is how the agent authenticates, not what it sends. A negation
        right before the verb, or governing the secret, discounts it."""
        start, end = verb.end(), self._object_end(verb.end())
        dest = _first(at["destination"], start, end)
        if dest is None or self.prohibited(verb.start(), TIGHT_WORDS):
            return False
        if self.p["leak_context"].search(self.text, start, dest):
            return False  # reporting a leaked or exposed key to a security contact discloses it
        secret = _first(at["secret_strong"], start, dest)
        if secret is not None:
            return not self.governs(start, secret)
        if not strong_verb or self.p["auth_context"].search(self.text, start, end):
            return False
        return self.p["secret_object"].match(self.text, start, dest) is not None

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


def _inside(pos: int, spans: list[tuple[int, int]]) -> bool:
    """True when `pos` falls inside one of the (start, end) spans, which are sorted by start."""
    k = bisect.bisect_right(spans, (pos, float("inf"))) - 1
    return k >= 0 and spans[k][0] <= pos < spans[k][1]


def judge(lex: Lexicon, sts: list[Statement]) -> list[Hit]:
    """Every rule that fires on the file's statements: per statement each rule at most once, refusals first."""
    doc = Doc(lex, sts)
    hits = doc.rule_hits()
    refused, asked = doc.exfil()
    for i in refused:
        hits[i].insert(0, Hit(*EXFIL, sts[i]))
    for i in asked:
        hits[i].append(Hit(*IN_REQUEST, sts[i]))
    found = [hit for i in sorted(hits) for hit in sorted(hits[i], key=lambda h: h.verdict != BLOCK)]
    return found + doc.trust_blocks(hits)


def guardrails(lex: Lexicon, sts: list[Statement]) -> dict[int, frozenset[str]]:
    """The statements that state a guardrail (a mandate word and a guarded topic), each with its topics, each
    topic marked by the statement's polarity (a prohibition, or a positive mandate). Encouragers are removed
    first: "never forget to commit secrets" and "no exceptions" prohibit nothing."""
    p = lex.p
    out = {}
    for i, st in enumerate(sts):
        text = p["encourager"].sub(" ", st.norm)
        if not p["guard_mandate"].search(text):
            continue
        sign = "never " if p["guard_prohibit"].search(text) else "always "
        if topics := {sign + (STEM.sub("", m.group()) or m.group()) for m in p["guard_topic"].finditer(text)}:
            out[i] = frozenset(topics)
    return out
