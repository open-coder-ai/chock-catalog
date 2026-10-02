---
name: dockerfile-compose-security
description: "Warns (observe rollout, never refuses) when a change to a Dockerfile, Containerfile or compose file adds: a base image with no tag, latest, an unresolvable ARG or no digest (stage-aware: FROM or COPY --from a stage is not an image); a final stage running as root; TLS or package-signature checks switched off; secret-named ENV/ARG/environment literals; COPY of key or .env files; remote ADD without checksum; RUN --security=insecure; chmod 777 or setuid; sudo, sshd, chpasswd; unpinned git clone; ONBUILD RUN; compose privileged, dangerous cap_add, unconfined seccomp/apparmor, devices, host namespaces, Docker socket or sensitive host mounts, database ports on every interface, untagged images. Left to other gates: one-line fetch-exec and ADD URL (block-fetch-exec-in-files), FROM/image at latest or untagged with a slash (block-unpinned-agent-components), scan-secrets token lines. Misses: build args overriding defaults, variables in commands, bake/k8s files. Friction, not a boundary."
metadata:
  chock.artifact: rule
  chock.enforcement: advise
  chock.coverage_without_chock: advisory
---

# Dockerfile and Compose Security

Warns (observe rollout, never refuses) when a change to a Dockerfile, Containerfile or compose file adds: a base image with no tag, latest, an unresolvable ARG or no digest (stage-aware: FROM or COPY --from a stage is not an image); a final stage running as root; TLS or package-signature checks switched off; secret-named ENV/ARG/environment literals; COPY of key or .env files; remote ADD without checksum; RUN --security=insecure; chmod 777 or setuid; sudo, sshd, chpasswd; unpinned git clone; ONBUILD RUN; compose privileged, dangerous cap_add, unconfined seccomp/apparmor, devices, host namespaces, Docker socket or sensitive host mounts, database ports on every interface, untagged images. Left to other gates: one-line fetch-exec and ADD URL (block-fetch-exec-in-files), FROM/image at latest or untagged with a slash (block-unpinned-agent-components), scan-secrets token lines. Misses: build args overriding defaults, variables in commands, bake/k8s files. Friction, not a boundary.

```
flag(container_change): Dockerfile|Containerfile|compose adds floating/undigested image, root final stage, TLS|signature off, literal secret, key-file COPY, privileged|cap_add|host ns|docker.sock|host-root mount, db port on 0.0.0.0
prefer: pinned tag@sha256, USER <uid>, RUN --mount=type=secret, cap_add narrow, named volumes; waiver: '# chock: allow <rule-id>', person only
```

This skill is advisory: the client reading it has no mechanism to enforce it. The same policy compiled by `chock` warns at commit, on an agent's file writes and at turn end. See https://github.com/open-coder-ai/chock
