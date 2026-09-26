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
- **config / waiver / legacy**: a pack switched off in `.chock/security.json`, a
  `// chock: allow <rule-id>` waiver, and an unrelated edit to a file that already breaks a rule
  (whole files are judged, so that edit is refused; the scenario makes that behaviour visible
  before an adopter meets it).

Every scenario carries a bad and a good example, and `tests/agent_kit` proves the bad one
triggers the scenario's rule and the good one triggers nothing. So a failure in the agent is
about the agent and the wiring, not a scenario that asked for something the engine would never
refuse.

## Which agents, and what each can show

Two routes put the policy in front of an agent.

- **Repo route**: `chock` installs the policy into the repository. This works today, from this
  catalog.
- **Plugin route**: install the java-security plugin from the agent's marketplace. This needs
  the 0.4.0 packages published to the plugin repositories first; until then they carry 0.3.0,
  which has eight rules.

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
- for Claude Code, its own PreToolUse command, run exactly as Claude Code runs it, denies a write
  of concatenated SQL and allows the bind-parameter version;
- on the repo route, the pre-commit hook refuses one commit and takes the other.

Run it once per workspace, and again if you ever see a hook error in the agent. `start` refuses to
begin while the hooks name files that are missing.

This check exists because the kit's first real run on Windows hit exactly this. A global `bin/`
ignore kept `.chock/bin/` out of the workspace. Claude Code reported a `SessionStart hook error`,
and every other hook failed silently. The agent then declined the SQL on its own, which looked like
a pass. An agent that declines on its own is graded `agent declined, gate not exercised`: not a
gate failure, and not evidence for the gate either. The doctor is the evidence.

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

## Tiers, and how long they take

| Tier | Scenarios | What it covers | Time per agent |
|---|---|---|---|
| `smoke` | 9 | a witnessed deny, a bait, a control, a quality rule, a test rule, a pack switched off, a waiver, legacy code | about 20 minutes |
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
- **Shaping:** `bait` scenarios are the soft measure. A bait failing on Copilot, which has only
  the ambient rule, while Claude Code corrects it after a refusal, is the expected difference
  between prose and a gate, not a bug.

A failure you cannot explain: keep the workspace, which holds the turn's diff and
`.git/agent-tests-results.jsonl`, and the agent's transcript. Together they are the whole
record.
