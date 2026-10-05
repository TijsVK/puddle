# 0005 — No base image of our own: run the team's own devcontainer image

Date: 2026-10-02
Status: accepted

## Decision

puddle does not ship or require a base image. A workspace boots from whatever OCI image the team's
devcontainer already uses, stock `mcr.microsoft.com/devcontainers/*` included. Everything puddle
needs inside the guest is **injected at sandbox boot**, not baked into an image.

`ghcr.io/infosupport/base-devimage-*` stays upstream's concern and is not carried into this repo.

## Why

Upstream's `base-devimage` is `mcr.microsoft.com/devcontainers/base:debian` plus three kinds of
thing, and none of them survives the move to a microVM:

| What it adds | Why it existed | Under a microVM |
|---|---|---|
| Docker CLI, compose plugin, iptables | Talking to the filtered Docker socket; the NAT rule that forced egress through the proxy | The filtered socket is gone (README, decision 2). Egress is forced by the VM's network floor, not iptables. Nested containers need a real `dockerd`, which the image never had |
| `vscode` stripped of sudo, added to `docker` | Hardening a shared-kernel container | The VM is the boundary. Root inside the guest is not root on the host |
| Node 24, claude-code/codex/copilot/opencode, markitdown, `~/.claude` dirs | Team tooling | A preference, not infrastructure. Belongs in the team's `devcontainer.json` (features, or their own image) |

Owning an image also means owning its release cadence, CVE patching and per-IDE variants, for no
remaining security benefit. Teams already maintain a devcontainer; puddle should run it, not
replace it.

## Consequences

What puddle injects at boot (via `--mount-file` / SDK mounts plus a startup script), and therefore
must work on an arbitrary Debian/Ubuntu/Alpine-based image:

1. **The vsock shim must be a static binary** (`puddle-agent`, musl, no runtime dependencies). The
   PoC's Python shim only works because `python:3.12` has Python. Stock devcontainer images do not
   guarantee Python or `socat`. The research doc's "since we own `base-devimage-*`, that is a
   controlled cost" no longer holds.
2. **Proxy environment for every entry point**, not only the startup script: SSH sessions (VS Code
   Remote-SSH, terminals) must see `HTTP(S)_PROXY`/`NO_PROXY`. That means writing
   `/etc/environment` and/or `/etc/profile.d/puddle.sh` at boot, and checking that msb's SSH path
   reads them (S6).
3. **Our CA certificate** for MITM path rules, once those land: dropped into the distro's trust
   store at boot (`update-ca-certificates` differs between Debian and Alpine), plus
   `NODE_EXTRA_CA_CERTS` and similar for runtimes that ignore the system store.
4. **`dockerd` for nested containers**: either required from the image (the devcontainers
   `docker-in-docker` feature) or injected by puddle. S7 decides which.
5. **The IDE server** is never prebaked. VS Code Remote-SSH downloads it through the proxy, so the
   VS Code update hosts become a default allowlist entry. This settles §4 question 1 of the MWE plan
   in favour of the download path.

Boot-time injection has a cost to watch: anything that has to happen before the user's first
process (shim up, env written, CA trusted) needs a deterministic startup hook in msb. If msb only
offers "run this script as the entrypoint", puddle's hook and the image's own entrypoint have to be
chained explicitly.

## Supersedes

- S2 in the research spike list ("Huddle's base image boots as a rootfs"). It is replaced by
  "a stock devcontainer image boots and puddle's injected pieces work in it", which the S6 and S7
  spikes cover by running on `mcr.microsoft.com/devcontainers/base:debian`.
- The `rootfs = ghcr.io/infosupport/base-devimage-<ide>` line in the README diagram, and step 1 and
  §4 of the MWE plan.

## Update 2026-10-02

The S7 spike (results in workspace: `docs/research/2026-10-s7-nested-docker-spike.md`) settled two of the
consequences above:

- **1.** The static shim exists as workspace: `poc/puddle-agent/`. It is injected
  with `--mount-file` and works unchanged on `devcontainers/base:debian` and `devcontainers/dotnet`.
- **4.** A stock image plus docker-ce installed in the guest runs the full nested battery, so
  `dockerd` can come from the team's image (e.g. the `docker-in-docker` feature). puddle supplies
  the dedicated `/var/lib/docker` disk and the proxy env for `dockerd` and nested containers
  (`~/.docker/config.json` `proxies`).
