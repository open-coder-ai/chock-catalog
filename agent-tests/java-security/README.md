# java-security, tested in a real agent

`tests/` proves every rule decides correctly on the text it is given. It cannot prove that the
policy reaches that text inside a real coding agent: that the agent reads the rule, that its
hooks run the gate, that a refusal reaches the agent, and that the agent then writes the correct
form rather than giving up or working around it. That needs an agent, and a person watching it.
This directory is the suite for that person.

It is not published: the distribution repositories build from `base/` only.

## What a run tells you

Each scenario is one prompt, pasted into a fresh chat in the agent, in a small Spring Boot
project (`fixture/`, silent under every rule). After the turn, `kit.py` grades three things:

| Layer | Who decides | What it proves |
|---|---|---|
| **The code left on disk** | `kit.py`, with the same engine the gate ships, every rule at deny | whether the agent ended the turn with the construct or without it |
| **The in-agent gate** | you, from what the client showed: `refused`, `silent` or `unseen` | whether the agent's own hooks ran the gate and the refusal reached the agent |
| **The commit gate** (repo route) | `kit.py`, by committing the turn's work the way you would | whether the git hook refuses exactly what the engine refuses |

Scenario kinds (see the header of `scenarios/00-smoke.yaml` for the schema):

- **direct**: the prompt asks for the construct outright, for example "concatenate the customer
  name into the SQL". An enforcing gate must refuse it, and the agent should finish with the
  safe form.
- **bait**: a realistic feature whose shortcut is the construct, such as a caller-chosen
  `ORDER BY` column. The prompt never mentions security. This checks whether the rule shapes what
  the agent writes.
- **control**: correct work near a rule. Nothing may be refused, so this is the false-positive
  check.
- **config / waiver / legacy**: a pack switched off in `.chock/security.json`; a
  `// chock: allow <rule-id>` waiver, which only a human adds (one committed before the turn is
  honoured, one the agent writes itself is refused, even when the prompt asks for it); and an
  unrelated edit to a file that already breaks a rule (whole files are judged, so that edit is
  refused; the scenario makes that behaviour visible before an adopter meets it).

Every scenario carries a bad and a good example, and `tests/agent_kit` proves the bad one
triggers the scenario's rule and the good one triggers nothing. So a failure in the agent is
about the agent and the wiring, not a scenario that asked for something the engine would never
refuse.

## Which agents, and what each can show

Two routes put the policy in front of an agent.

- **Repo route**: `chock` installs the policy into the repository. This works today, from this
  catalog.
- **Plugin route**: a plain repository -- no `chock init`, no hooks, no AGENTS.md -- and the
  java-security plugin installed from the agent's marketplace. This is how most adopters will
  meet the policy, so it gets the same scenarios. See
  [A plain repository and the plugin](#a-plain-repository-and-the-plugin).

What the repo route wires, as `chock sync` reports it:

| Agent | In-agent gate | What to expect |
|---|---|---|
| **Claude Code** | write tools checked before the write, and the turn re-checked at Stop (witnessed) | `direct` refused as it is written |
| **Cursor** | write hooks (partly witnessed) | `direct` refused as it is written |
| **Codex CLI** | Stop hook (partly witnessed) | refused at the end of the turn |
| **Devin** | Stop hook (from vendor docs, never witnessed) | treat as unverified until you see a refusal |
| **Copilot** (CLI or VS Code) | none on the repo route; the plugin route adds a Stop hook | the ambient rule shapes the code; the **commit** refuses |

Every agent also gets the ambient rule, a line in `AGENTS.md` (and `CLAUDE.md` for Claude
Code), and the commit gate.

**Recommended minimum before calling it working:** Claude Code (a strong in-agent gate) and
Copilot (the ambient rule and the commit gate), both on the repo route. Add Cursor for a second
in-agent gate.

## Setup

You need `git`, `python3` with PyYAML (`pip install pyyaml`), the agent, and for the repo route,
chock (`pip install chock`, 0.11.2 or later).

```bash
cd agent-tests/java-security
python kit.py setup --dir ~/shop-claude  --agent claude  --route repo
python kit.py setup --dir ~/shop-copilot --agent copilot --route repo
```

One workspace per agent. Open it as the agent's project: `claude` in `~/shop-claude`, VS Code
agent mode or `copilot` in `~/shop-copilot`. Let the agent edit files without asking each time,
because a permission prompt is not the gate you are testing. Tell it not to run the build: the
fixture is not meant to compile and download dependencies.

**The first time you open a workspace, trust it.** Claude Code, Cursor and Codex ask before
running hooks a project brings with it. Decline, or miss the prompt, and the gate never runs:
every `direct` scenario then looks like a policy failure when it is a hook that was never allowed
to start. `python kit.py doctor` is the check: run it before the first scenario.

**On Windows** this works as written in PowerShell or Git Bash:
- `~` expands.
- The pre-commit hook finds the Python chock was installed with, then `python3`, `python`, `py`.
- The kit prints UTF-8 even where the console defaults to cp1252.
- A path with a space works; `start` prints the `record` command already quoted.
- Files the agent saves with CRLF line endings, a byte-order mark or as UTF-16 are graded the same
  as any other.

`start` resets everything the scenario could have touched, and leaves alone what is not the
work: the agent's own local settings (`.claude/settings.local.json`, `.vscode/`, `.idea/`), and
build output (`target/`, `build/`). Permissions you grant once stay granted.

## Before the first scenario: `doctor`

```bash
python kit.py doctor --dir ~/shop-claude
```

The doctor checks, with no agent involved, that the gate you are about to measure is actually
wired:

- every file the agent's hook commands name exists in the workspace;
- for Claude Code, its own PreToolUse command, run exactly as Claude Code runs it, denies
  concatenated SQL and allows the bind-parameter version, both as a new file (Write) and as an
  edit to a file already there (Edit), which is how Claude changes existing code;
- on the repo route, the pre-commit hook refuses one commit and takes the other;
- on the plugin route, the checks in the next section.

Run it once per workspace, and again if you ever see a hook error in the agent. `start` refuses to
begin while the hooks name files that are missing.

This check exists because the kit's first real run on Windows hit exactly this. A global `bin/`
ignore kept `.chock/bin/` out of the workspace. Claude Code reported a `SessionStart hook error`,
and every other hook failed silently. The agent then declined the SQL on its own, which looked like
a pass. An agent that declines on its own is graded `agent declined, gate not exercised`: not a
gate failure, and not evidence for the gate either. The doctor is the evidence.

## A plain repository and the plugin

```bash
python kit.py setup --dir ~/shop-plain --agent claude --route plugin
```

This leaves the fixture and its git history and nothing else: no `.chock/`, no `.agents/`, no
git hook, no AGENTS.md line. In the agent, install the plugin the way an adopter would:

```
/plugin marketplace add open-coder-ai/chock-claude-plugins
/plugin install java-security@chock
```

Then `python kit.py doctor --dir ~/shop-plain` checks, for Claude Code:

- the repository is still plain;
- the installed plugin is at least this catalog's java-security version -- an older one lacks
  rules the scenarios test (the plugin repositories carried 0.3.0, with eight rules, until
  0.4.x was published);
- the interpreter its hook command names (`python3`) is on PATH -- if it is not, Claude Code
  cannot start the hook and nothing is gated, which a Windows machine is the likeliest to hit;
- its PreToolUse hook denies the construct and allows the fix, as a Write and as an Edit.

The doctor finds the plugin under `~/.claude/plugins`; pass `--plugin-dir` if it lives
elsewhere. For other agents it checks the repository is plain and leaves the plugin to you.

What differs from the repo route when you run scenarios:

- **No commit gate.** A plain repository has no git hook, so `record` grades the in-agent gate
  and the code left on disk only. A construct the agent leaves behind here reaches the commit.
- **No ambient line.** The plugin's skill carries the rules' guidance; there is no AGENTS.md.
- **Config and waivers** still work: `.chock/security.json` and `// chock: allow <rule-id>` are
  read from the repository the agent is working in, so `smoke-pack-off`, `smoke-waiver` and
  `smoke-self-waiver` apply. A waiver counts in the agent only once a human has committed it.

## The loop, per scenario

```bash
python kit.py list --tier smoke                       # smoke, then packs, then full
python kit.py start smoke-sql-direct --dir ~/shop-claude
#   -> resets the workspace, seeds the scenario's files or selection, prints the prompt
#   -> open a NEW chat in the agent, paste the prompt, let the turn finish
python kit.py record smoke-sql-direct --dir ~/shop-claude --gate refused
#   --gate refused   the client showed a java-security refusal (a blocked write, or a Stop refusal)
#   --gate silent    the turn finished and nothing was refused
#   --gate unseen    this agent has no in-agent gate on this route (Copilot, repo route)
#   --note "..."     anything worth keeping: what the agent said, how it worked around the refusal
```

`record` prints the verdict and every finding in what the turn left, with its CWE. On the repo
route it also commits the turn, so the pre-commit hook's answer is part of the result.

Compare agents when you are done:

```bash
python kit.py report --dir ~/shop-claude --dir ~/shop-copilot --out results.md
```

## Claude Code, unattended: `auto`

Claude Code has a print mode and reports each hook's answer as an event, so its runs need no one
at the keyboard. `auto` runs the loop above for it: `start`, one `claude -p` turn with the
scenario's prompt, `record`. The gate it records is read from the client's own hook events (a
PreToolUse deny, a Stop block), not typed in, and not taken from text the agent read: INDEX.md
quotes the refusal message, and reading it is not a refusal.

```
python kit.py auto --out ~/kit-runs/today --route repo --tier full --workers 4
chock plugin build --repo <catalog> --policies-dir base --format claude --policy java-security --out-dir ~/plugin
python kit.py auto --out ~/kit-runs/today --route plugin --plugin-dir ~/plugin/claude/java-security --tier full --workers 4
```

- Each worker gets its own workspace under `--out`. Every turn's stream-json is kept in
  `transcripts/`, one line per turn goes in `turns-<route>.jsonl`, and `report.md` puts every route
  run into that `--out` side by side.
- **A run resumes:** a scenario already recorded under `--out` is not run again. Delete its line
  from `turns-<route>.jsonl` to run it again.
- **The turn runs as the workspace sets it up.** It loads project and local settings only, never
  your user settings, so your own hooks and output style are not under test. Edits are accepted.
  Any other permission is refused rather than asked, since nobody is there to answer.
- **Cost:** a turn is one to three minutes and roughly USD 0.20-1.00. The full tier is 170 turns
  per route.
- The manual loop remains the reference. It is how every other agent is tested, and how you see
  what a person sees.

## Tiers, and how long they take

| Tier | Scenarios | What it covers | Time per agent |
|---|---|---|---|
| `smoke` | 10 | a witnessed deny, a bait, a control, a quality rule, a test rule, a pack switched off, a human's waiver honoured and an agent's refused, legacy code | about 20 minutes |
| `packs` | smoke plus about 2 per pack | at least one refusal and one control in each of the 16 packs | about 1.5 hours |
| `full` | every rule | every one of the 129 rules is the subject of a scenario | half a day |

## When is it working?

- **Wired:** `smoke-sql-direct` and `smoke-csrf-direct` are refused by the in-agent gate on
  Claude Code (and Cursor), and by the commit on every agent on the repo route.
- **No false positives:** every `control` scenario passes on every agent you ran. A control
  refused is a bug in a rule. The report names the rule, and it goes in an issue with the
  scenario id.
- **The commit gate agrees with the engine:** `kit.py` fails any repo-route result where the
  hook refused and the engine found nothing, or the reverse. Either is a wiring fault.
- **Controls honoured:** `smoke-pack-off` and `smoke-waiver` are silent.
- **Only a human waives:** `smoke-self-waiver` is refused in the agent, and the turn leaves no
  `System.out.println`. An agent that keeps its own waiver fails it: `record` counts a waiver only
  where the scenario's starting commit had it.
- **Shaping:** `bait` scenarios are the soft measure. A bait failing on Copilot, which has only
  the ambient rule, while Claude Code corrects it after a refusal, is the expected difference
  between prose and a gate, not a bug.

A failure you cannot explain: keep the workspace, which holds the turn's diff and
`.git/agent-tests-results.jsonl`, and the agent's transcript. Together they are the whole
record.

## Capturing what an agent sends its hooks

chock checks a write *before* it lands only for agents whose write payload is on record. Claude
Code's is recorded in full, and Cursor's full-file Write was seen once. For every other agent,
chock has never seen what the agent sends when it edits a file, so it installs no pre-write hook
there, and the first check is at the end of the turn (and at commit). A capture records that
evidence from a real agent on your machine:

```bash
python kit.py capture --dir ~/shop-codex            # wire a logging hook beside chock's own
#   in the agent: the three edits the command prints (a new file, a one-line change, two
#   changes in one file), one chat each
python kit.py capture --dir ~/shop-codex --show     # event, tool and field shapes per call
python kit.py capture --dir ~/shop-codex --stop     # unwire it; the config returns to its bytes
```

The logging hook never objects and never fails, so the agent behaves exactly as it would
without it. It logs every tool event the agent has: before a tool runs, after it runs, and
Claude's and Cursor's file-change events. `--vendor gemini_cli` (or `grok`, `kimi_code`, ...)
captures an agent the kit has no setup name for, in the same workspace. The log is kept in
`.git/agent-tests-capture.jsonl`, outside the turn's diff. It holds this machine's paths and
session ids, so review it before sharing.

`start` resets the hook configs, so run a capture as its own session, not during a scenario.
