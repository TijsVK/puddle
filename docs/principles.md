# Puddle's principles

What Puddle promises the person using it, and what it never does. They name no component: if any
part of Puddle were rewritten from scratch, they would still hold. The [ADRs](adr/README.md) and
[spec pages](spec/) describe how each part honours them. A change that breaks a principle is a bug,
even when every test passes; if a change seems to need it, don't land that part, and open an issue
instead. Changing a principle is the project owner's call, recorded in an ADR.

The "rules out" lines are examples, not the whole boundary.

## 1. The sandbox is invisible to the work inside it

*Why:* a sandbox people have to work around gets switched off, so it protects only if tools run in
it as they would without it.

- **This means:** everything the user allowed works as on an unsandboxed machine: downloads,
  many parallel connections, long transfers, sleep and resume, short network drops. Reliability and
  speed bars come from real tools at their maximum (package managers, image builders), not from tidy
  synthetic numbers.
- **This rules out:** a concurrency cap below what real tools open; a bar set at "typical" load that
  real tools exceed; stalls, resets or timeouts a tool would not see outside Puddle.

## 2. Only the user says no

*Why:* Puddle can't know what someone's work needs, and a refusal it makes up is a broken build
nobody can explain.

- **This means:** a fresh install has decided nothing. A request that no rule matches is recorded and
  waits in the inbox until the user answers; nothing is denied in advance, telemetry hosts included.
  (How the tool's connection behaves meanwhile, held open or refused with "waiting for approval", is
  a spec choice; the request itself stays open.) Automated help (rule sets, suggestions, an AI judge)
  may at most allow what is clearly safe; where it would say no, the user is asked instead.
- **This rules out:** a built-in deny list; denying a request, or not recording it, because its
  workspace asks about many hosts; a helper's "no" turned into a deny rule. A workspace flooding the
  inbox is bounded without refusing: grouping, back-pressure, storage caps that keep requests
  waiting.

## 3. Limits are the user's settings

*Why:* Puddle runs on many machines for many kinds of work; a limit right for one is wrong for
another, and the person at the keyboard knows which.

- **This means:** every restriction on what a workspace may reach (host loopback, local network,
  link-local, cloud metadata) is a setting with a global default and a per-workspace override,
  blocked by default where it guards something sensitive. Turning one on only permits: each
  destination still needs an allow. A block names the setting that would lift it.
- **This rules out:** address classes blocked for good; a limit that only a config file or a rebuild
  can change; a block that doesn't say which setting caused it. (The guards that protect Puddle
  itself from the workspace are not such limits: see 4.)

## 4. The workspace is untrusted and holds no keys

*Why:* whatever runs in a workspace (an agent, a dependency's install script) may be hostile and is
root in its VM; the VM boundary and Puddle's proxy are all that stand between it and the user's
machine and accounts. A wrong allow is far worse than a wrong refusal.

- **This means:** the VM is the boundary and every connection out goes through Puddle. Secrets are
  added on the way out; the workspace only ever sees a placeholder. The workspace can't reach
  Puddle's own endpoints, see its API token, or change its own rules, settings or host-owned
  configuration. Decisions use what the host knows (the route a connection came in on, the host
  clock), never what the guest claims. A check that can't be completed refuses that connection; it
  never lets it through. Only the user can weaken this, by an explicit choice Puddle warns about
  (attaching a desktop IDE trusts the workspace); Puddle's API always needs its token.
- **This rules out:** a secret in the guest's environment, files or memory; trusting a guest-supplied
  name, id or time; a workspace editing its own start-up scripts or rules; treating a user account
  inside the VM as the boundary.

## 5. Any machine, any network

*Why:* Puddle is for many developers on many machines, client machines included; nobody can know in
advance which proxies, VPNs or policies those have.

- **This means:** Puddle detects its environment and adapts by itself: upstream proxies, PAC, proxy
  sign-in, TLS-intercepting proxies and their roots, VPNs, split DNS. What it can't fix, it explains
  with the exact fix. Tests simulate the environments no single machine has.
- **This rules out:** designing around one machine's proxy, VPN, certificates or RAM; assuming
  direct internet access; a setup that needs an IT department; "it works here" as the bar.

## 6. Nothing fails silently

*Why:* a failure without a reason looks like a broken tool, and the user can't fix what they can't
see.

- **This means:** every refusal, hold, block and unsupported case says what happened, why, and the
  way out (the rule, the setting, the missing prerequisite), to the user and, where it can, to the
  tool. A weaker guarantee is stated plainly where the user chooses it (attaching a desktop IDE makes
  the workspace trusted). What Puddle does on its own is shown: a process killed for memory, a file
  it restored, a certificate it reused.
- **This rules out:** a dropped connection without a reason; a generic error where the cause is
  known; an unsupported feature failing like a network error; softened wording for a refusal ("held
  back" for "denied"); a trade-off mentioned only in the docs.

## 7. Your work is never lost by accident

*Why:* a workspace holds work that may exist nowhere else yet.

- **This means:** a workspace's data survives rebuilds, restarts, Puddle quitting and crashes.
  Deleting it is its own explicit act that first shows what would be lost (uncommitted changes,
  unpushed commits, stashes) and asks for confirmation.
- **This rules out:** a rebuild, update or clean-up that resets a workspace's data; deleting a
  workspace as a side effect of another action; a one-click delete.

## 8. Nothing leaves, and nothing third-party arrives, without consent

*Why:* Puddle runs in the middle of people's work, sometimes on a client's machine; it may not report
on them, or accept terms on their behalf.

- **This means:** Puddle's own telemetry and crash reports are opt-in, and nothing is sent without
  consent. Third-party software with its own terms (a vendor's server, extensions) arrives only after
  the user accepted those terms; Puddle never bundles such software, and never installs or
  recommends extensions. Telemetry of the user's own tools is ordinary traffic under principle 2.
- **This rules out:** telemetry on by default; a crash report sent automatically; Puddle installing
  an extension; accepting a licence for the user.

## 9. Portable, and fixed at the source

*Why:* Puddle runs on Windows and Linux and keeps macOS possible; per-OS patches around a
dependency's bug multiply and hide the bug.

- **This means:** shared code makes no single-OS assumption. Per-OS code is only for real OS
  integration (proxy discovery, credential and certificate stores, IPC permissions, installers),
  behind a portable interface, and a maintained cross-platform crate beats our own per-OS code. A bug
  in a dependency is fixed in the dependency (our public fork of it, with the fix prepared for
  upstream); any stopgap on our side is temporary and has an issue for its removal.
- **This rules out:** `cfg(windows)` retries or sleeps around a runtime bug left in place; OS-specific
  paths or assumptions in shared code; a feature that silently works on one OS only.

## 10. Quality is not negotiable

*Why:* Puddle is a security tool written largely by agents; tests and gates are what make its
behaviour trustworthy.

- **This means:** every behaviour is tested at the tier where it can break, riskiest assumptions
  first; every gate passes on every change, and gates only grow ([STANDARDS](STANDARDS.md)). The
  reasons behind the design live in this repository, readable by an outside contributor. The UI meets
  WCAG 2.2 AA.
- **This rules out:** skipping, ignoring or weakening a failing test or gate to land; bypassing the
  hooks; a decision whose reason exists only outside this repository.
