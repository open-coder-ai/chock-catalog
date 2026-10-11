# Ask Credential Switching

`ask-credential-switching` · rule · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | asks — asks before a matched shell command runs |
| **Manifest tier** | `enforcement: advise` (propagation and index ranking; not what it blocks) |
| **Mechanism** | guard script `ask-credential-switching.py` |
| **Reaches** | `best-effort` on Claude Code, `enforceable` on Cursor, once `chock sync` has run — the tool call is refused before it runs, on a hook that is actually wired up. Claude Code's PreToolUse fails **open**, so a crashed hook silently allows; Cursor's can be told to fail closed, but does not by default |
| **Compiles to** | `pre-tool-use`, `ambient-rule` |
| **Eval cases** | 65 total, 65 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Best effort, ask only. Asks a person before a shell command switches the identity later commands act as: aws --profile, AWS_PROFILE= or AWS keys (also $env:), sts assume-role, configure set of a key; gcloud account, configuration, login or impersonation; az account set, az login as a principal or identity; kubectl use-context or set-credentials; writes to ~/.aws, ~/.config/gcloud, ~/.azure. Names in .chock/credential-allowlist.json pass. Misses: scripts, SDKs, env files, credential_process.

## What it solves

A developer's machine usually holds more than one identity: a dev profile, a production profile, an admin role
it can assume, a second Kubernetes context. An agent that types `aws --profile prod`, `export AWS_PROFILE=prod`,
`aws sts assume-role`, `gcloud config set account`, `az account set` or `kubectl config use-context prod` acts
with whatever that identity may do, and a prompt-injected agent can pick the strongest one on purpose. These
switches are routine in correct work, so this guard never refuses one: it asks the person, naming the identity,
before the command runs. Reads (`aws configure list`, `gcloud config list`, `az account show`) stay silent.

## How it works

A guard script, `implementations/ask-credential-switching.py`, run before the agent executes a Bash command. It inspects the proposed command and exits non-zero to refuse it.

The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:

```text
ask_person: switch_identity(aws(--profile|AWS_PROFILE=|AWS_*KEY*=|$env:|sts_assume-role|configure_set_cred)|gcloud(set_account|configurations_activate|auth_login|impersonate)|az(account_set|login_principal|login_identity)|kubectl(use-context|set-credentials)|write(~/.aws|~/.config/gcloud|~/.azure)); say(identity), ask(intended?)
pass: reads(configure_list|config_list|account_show), names_in(.chock/credential-allowlist.json@HEAD)  # person-only, own commit
```

## Which primitive it becomes

A **PreToolUse guard**. `recompile` writes `.chock/compiled/ask-credential-switching/pre-tool-use/pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent consults the guard script before running a Bash command. Until that install runs, the fragment is compiled and enforces nothing, and coverage says so.

## Installing it

```bash
chock add ask-credential-switching
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/ask-credential-switching  <your-repo>/.agents/policies/ask-credential-switching
cd <your-repo> && chock sync --repo .
```

## Customising it

List the identities an agent may switch to without asking in `.chock/credential-allowlist.json`, one list per
provider: `{"aws": ["dev"], "gcloud": ["dev@example.com"], "azure": ["dev-subscription"], "kubernetes":
["kind-dev"]}` (profile, role ARN or access key id; account, configuration or service account; subscription or
principal; context or user). The guard reads the file from HEAD only, so commit it yourself: an agent's edit
never counts, and protect-agent-config refuses agent writes under `.chock/`. Any other key, or a value that is
not a list of names, and none of the file is honoured.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals ask-credential-switching
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/ask-credential-switching/`](../../base/ask-credential-switching/) · [all policies](../README.md)
