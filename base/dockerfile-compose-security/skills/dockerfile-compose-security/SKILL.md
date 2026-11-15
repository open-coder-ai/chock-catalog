---
name: dockerfile-compose-security
description: "Blocks (some rules ask) when a change to a Dockerfile, Containerfile or compose file adds: a base image with no tag, a floating tag (latest, stable, edge, lts) or an unresolvable ARG; a final stage running as root; TLS or signature checks off; secret ENV/ARG/environment literals; COPY of key or .env files; remote ADD without checksum; fetch piped to a shell; RUN --security=insecure; chmod 777 or setuid; sudo, sshd, chpasswd; unpinned git clone; ONBUILD RUN; compose privileged, broad cap_add, unconfined profiles, devices, host namespaces, runtime socket or host-root mounts, DB ports on every interface. A one-line form goes to block-fetch-exec-in-files, block-unpinned-agent-components or agentic-code-security only where that gate is installed and reads the file; scan-secrets lines always. Misses: digest pinning (a version tag passes), build args overriding defaults, commands in variables, aliases or $'' quoting, bake and k8s files, extends or include, other file names, a moved file. Friction, not a boundary."
metadata:
  chock.artifact: rule
  chock.enforcement: block
  chock.coverage_without_chock: advisory
---

# Dockerfile and Compose Security

Blocks (some rules ask) when a change to a Dockerfile, Containerfile or compose file adds: a base image with no tag, a floating tag (latest, stable, edge, lts) or an unresolvable ARG; a final stage running as root; TLS or signature checks off; secret ENV/ARG/environment literals; COPY of key or .env files; remote ADD without checksum; fetch piped to a shell; RUN --security=insecure; chmod 777 or setuid; sudo, sshd, chpasswd; unpinned git clone; ONBUILD RUN; compose privileged, broad cap_add, unconfined profiles, devices, host namespaces, runtime socket or host-root mounts, DB ports on every interface. A one-line form goes to block-fetch-exec-in-files, block-unpinned-agent-components or agentic-code-security only where that gate is installed and reads the file; scan-secrets lines always. Misses: digest pinning (a version tag passes), build args overriding defaults, commands in variables, aliases or $'' quoting, bake and k8s files, extends or include, other file names, a moved file. Friction, not a boundary.

```
flag(container_change): Dockerfile|Containerfile|compose adds floating image (no tag, latest, stable, edge), root final stage, TLS|signature off, literal secret, key-file COPY, privileged|cap_add|host ns|docker.sock|host-root mount, db port on 0.0.0.0
prefer: pinned tag@sha256, USER <uid>, RUN --mount=type=secret, cap_add narrow, named volumes; waiver: '# chock: allow <rule-id>', person only
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` blocks at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
