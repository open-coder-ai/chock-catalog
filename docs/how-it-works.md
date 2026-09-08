# How it works, in full

The README's [_How it works_](../README.md#how-it-works) section condenses the argument below
to fit around the diagram. Nothing here was dropped — this is the prose it was condensed from,
verbatim.

## Why this instead of a prompt

You have already told your agent not to commit secrets. It agreed. Then the session got
long, the instruction moved to the middle of the context window, and it did it anyway.

Gates run in **git**, so they hold no matter which agent — or which human — is at the
keyboard. And where a policy cannot reach an agent, `coverage.json` says `unsupported`
rather than quietly omitting the row — an understated number is the same failure as an
overstated one.

## How it works

One folder per policy. `manifest.yaml` declares identity and either a gate or rule text;
`chock sync` turns that into artifacts for whichever agents you use.

The same policy reaches different levels on different agents, and `coverage.json` records
every pair.

## Works with the agent you already use

Thirteen adapters, generated from one `AGENTS.md`. The rules live in one place; the adapters
exist because agents look for different filenames.

`claude` · `copilot` · `cursor` · `gemini` · `codex` · `aider` · `windsurf` · `devin` ·
`grok` · `kimi-code` · `replit` · `tabnine` · `vscode`

```bash
chock init . --agent-agnostic   # generate all of them
chock init . --agents cursor    # or just yours
```

## The content is yours

```bash
cp -r base/scan-secrets  <your-repo>/.agents/policies/scan-secrets
cd <your-repo> && chock sync --repo .
```

Copying the folder produces **byte-identical** compiled output to `chock add` — there
is no registration step and nothing `add` does that a copy misses. Then edit it. `recompile`
reads your copy as the source, so a changed regex reaches the compiled gate and changes what
gets blocked.

Nothing upstream overwrites your version. That is the entire reason these live outside the
framework: a bundled policy is one the framework owns and replaces on upgrade, which makes
customisation impossible.

Add your own token formats. Loosen a threshold. Delete the rules you disagree with.

## This repo runs what it publishes, in full

The README's [_This repo runs what it publishes_](../README.md#this-repo-runs-what-it-publishes)
condenses the three paragraphs below into one. Verbatim, uncut:

The catalog is a Chock adopter. `.agents/policies/` holds every `base/` policy — the
catalog protects itself the same way it asks any open-source repo to — and the first
commit after adoption was rejected by `protect-main-branch`. One is installed but
disabled with its reasons written in `.chock/config.yaml`: `verify-dependency-exists`
watches dependency manifests this repo does not have.

That is not a flourish. A worked example that is a repository cannot drift from the
instructions the way a README snippet does — and running it has already found four framework
bugs that no test caught, including a freshness check whose verdict depended on the caller's
working directory and an `add` that could not see this catalog's newest tree.

CI keeps two things apart on purpose: **what this repo runs** (the `base/` tier — the
compliance and agentic-security packs stay uninstalled because, by their own doctrine,
they only earn their place where they apply, and this repo ships no agentic system and
falls under no covered regulation) and **what this repo ships** (every published policy,
staged into a throwaway repo the way an adopter installs them). A catalog should still
publish more than it is bound by, and [the reasoning is written down](README.md).
