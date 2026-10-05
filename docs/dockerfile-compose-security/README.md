# Dockerfile and Compose Security

`dockerfile-compose-security` · hook · enforces

<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->

| | |
| :--- | :--- |
| **Type** | `rule` |
| **On Claude Code** | blocks — blocks on an agent's file writes and at turn end |
| **Manifest tier** | `enforcement: block` (propagation and index ranking; not what it blocks) |
| **Mechanism** | script gate |
| **Reaches** | `enforced-at-commit` — the command exits non-zero and the commit does not happen |
| **Compiles to** | `git-hook`, `ci-gate`, `ambient-rule` |
| **Eval cases** | 34 total, 34 executable |
| **Enabled by default** | yes |

<!-- generated:end -->

## What it is about

Blocks (some rules ask) when a change to a Dockerfile, Containerfile or compose file adds: a base image with no tag, latest, an unresolvable ARG or no digest (stage-aware: FROM or COPY --from a stage is not an image); a final stage running as root; TLS or package-signature checks off; secret-named ENV/ARG/environment literals; COPY of key or .env files; remote ADD without checksum; fetch piped to a shell; RUN --security=insecure; chmod 777 or setuid; sudo, sshd, chpasswd; unpinned git clone; ONBUILD RUN; compose privileged, broad cap_add, unconfined profiles, devices, host namespaces, runtime socket or host-root mounts, database ports on every interface, untagged images. A one-line form is left to block-fetch-exec-in-files, block-unpinned-agent-components or agentic-code-security only where that gate is installed and reads the file; scan-secrets lines always. Misses: build args overriding defaults, commands in variables, aliases or $'' quoting, bake and k8s files. Friction, not a boundary.

## What it solves

An agent asked to make a container work reaches for the shortcuts that make it work fastest -- run as root, mount the Docker socket, turn on privileged, skip TLS, bake a password into an ENV, build FROM whatever tag is current. Each one hands the container, or whoever controls a base image or URL, the host. This gate reads the Dockerfiles and compose files a change writes, follows build stages, ARGs, line continuations, heredocs and YAML anchors, and names each such construct with its weakness and fix. It warns while its false-positive rate is measured, then blocks; forms another gate already refuses on one line are left to that gate.

## How it works

A declarative `script` gate, evaluated on `commit` and `tool_use`, action `block`.

Parameters, from `manifest.yaml`:

- `script`

On a match it prints:

> A Dockerfile or compose change weakens the container's isolation or supply chain (each finding names its rule, weakness and fix). Pin images by tag and digest, end the final stage with a non-root USER, keep TLS and signature checks on, pass secrets with RUN --mount=type=secret or compose secrets, and drop privileged, broad cap_add, host namespaces and host-root or Docker socket mounts. Deny-tier findings block; ask-tier findings ask a person. A person may keep a reviewed finding with '# chock: allow <rule-id>' on the line or the comment line above it; in the agent only a line already committed in HEAD counts, so an agent asks a person.

## Which primitive it becomes

A **git hook**. `recompile` writes `.chock/compiled/dockerfile-compose-security/git-hook/gate.json`, and `install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather than the intent.

## Installing it

```bash
chock add dockerfile-compose-security
chock sync .
```

Or copy the folder — it does the same thing, byte for byte:

```bash
cp -r base/dockerfile-compose-security  <your-repo>/.agents/policies/dockerfile-compose-security
cd <your-repo> && chock sync --repo .
```

## Customising it

Each finding names its rule id (dk-* for Dockerfiles, cm-* for compose). A person keeps a reviewed construct with `# chock: allow <rule-id>` on the line or on the comment line directly above it (for a Dockerfile, above the instruction), committing from their own shell; in the agent a waiver counts only for a line already in HEAD. Rules carry a deny or ask tier for the later enforce stage; until then every finding warns.

Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.

After any edit:

```bash
chock sync --repo .   # rebuild the compiled artifact
chock check           # check it still conforms
chock check --only evals dockerfile-compose-security
```

---

[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.

Source: [`base/dockerfile-compose-security/`](../../base/dockerfile-compose-security/) · [all policies](../README.md)
