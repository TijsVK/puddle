# 0006 — Workspace storage: a named msb disk volume per workspace

Date: 2026-10-04
Status: **accepted** for the storage method, seeding and lifecycle (decided 2026-10-04).
**Proposed** for the requirements that came out of the measurement rerun (marked *proposed*
below) until they are confirmed.
Evidence: workspace storage measurements on msb 0.7.6, rerun 2026-10-04 with a sounder method. The
measurement record and raw logs predate this repository and are not published; the numbers that
decide it are below.

## Context

The original plan assumed each workspace is a Windows folder bind-mounted into the microVM. On msb
0.7.6 that doesn't work:

- **It is broken.** Every rename on a virtiofs bind of an NTFS folder returns `EIO` and poisons the
  directory until the sandbox restarts (upstream
  [#1638](https://github.com/superradcompany/microsandbox/issues/1638), open, unfixed in 0.7.6 and
  on the 0.7.7 / 0.8.0 prep branches). `git clone`, `checkout` and `init` fail 5/5, and so does
  every dotnet build. Host edits produce no inotify events in the guest, the tree is
  case-insensitive unless the folder is flagged, and a junction makes its whole directory
  unreadable.
- **It is slow, independent of #1638.** 26× native NTFS for `npm ci` (426 s vs 16 s), 20× for warm
  `git status`, 20× for small-file creates; the acceptance bar was 2×. Against a guest-local volume
  it is 64×, 98× and 480×. `stat-virt=off` doesn't fix it: the virtiofs round trip into Win32
  dominates.
- **Guest-local ext4 is fast.** A named msb disk volume (ext4 on virtio-blk) performs the same as
  an owned disk, the rootfs and WSL2 ext4 on every workload, and beats native NTFS with Defender:
  2.4× for `npm ci`, 5× for `git status`, 3.7× for checkout, 1.36× for a cold dotnet build.
- **The named volume behaves.** It survives `msb rm` + recreate (same HEAD, clean `fsck`, a
  549-file manifest matches), msb refuses a second sandbox attaching it while the first runs,
  ext4 replays cleanly after a VMM kill (10/10), and a sandbox with one is created in about 1.2 s,
  the same as without.

Two findings from the rerun put requirements on puddle rather than on the choice:

- **Git with default settings lost HEAD in 5/5 VMM kills;** with `core.fsync=committed`, 5/5 repos
  passed `git fsck --full`.
- **Disk images never shrink on delete.** The volume held 8.8 GB allocated after `rm -rf` of
  everything; `fstrim` in the guest brought it to 104 MB. msb mounts volumes without `discard`. The
  layered root disk can't be trimmed at all (`discard not supported`), and held 5.4 GB.

## Decision

1. **Each workspace is a named msb disk volume** (`ws-<id>`, ext4, `--mount-named
   ws-<id>:/workspaces/<name>:kind=disk,size=N`) in puddle's private `MSB_HOME`: puddle bundles
   its own msb runtime, so its images and volumes never mix with an msb the user installed
   separately. No Windows folder is bind-mounted as the workspace.
2. **Code gets in by cloning inside the VM** through puddle's proxy in the first milestone, with
   git HTTPS credentials injected by the proxy. **"Start from my Windows checkout"** is the first
   thing after it; the measurements showed the mechanism works (a read-only bind of the checkout +
   `git clone` inside the guest: 0.6 s for `nestjs/nest`, no #1638 on reads). Prefer `clone` over
   `cp -a`, which carries the host's `core.filemode=false` / `core.symlinks=false` into the guest
   repo. A plain file copy only as an explicit option, if at all.
3. **The volume outlives the sandbox.** Rebuilding a sandbox (image bump, config change, msb
   upgrade) reattaches the same volume. **Deleting a workspace is a separate, explicit action** that
   first lists uncommitted changes, unpushed commits and stashes, and asks. A recycle bin later if
   people ask for undo.
4. **No Windows access to the live tree in the first milestone or v1.** Mounting sandbox folders
   into Windows (a drive or network share for copying out) is an optional feature after v1.
5. **Nested Docker's data stays on an owned disk** (`--mount-owned /var/lib/docker:kind=disk`):
   it is per sandbox and disposable, so it should die with the sandbox. Flat root disks are not used.

### Requirements from the rerun (proposed)

6. **Guest git uses `core.fsync=committed`.** There is no image of our own to bake it into
   (ADR 0005), so puddle's boot-time guest setup writes it into the system gitconfig
   (`git config --system core.fsync committed`, falling back to `/etc/gitconfig` directly), next to
   the other boot setup (inotify limits, proxy config, PATH fix, git identity). The write cost is
   not measured yet.
7. **puddle trims workspace volumes:** `fstrim` on the volume's mount point when a sandbox is
   stopped by puddle (before the VM goes down), plus a manual "reclaim space" action per workspace.
   A timer for long-running sandboxes can come later if disk use shows it is needed.
8. **A second attach is refused cleanly.** puddle tracks which sandbox has a workspace's volume and
   refuses a second attach itself, with a message naming the sandbox that holds it, rather than
   relying on msb's `already attached with an incompatible disk mode`. If msb does refuse a create,
   puddle removes the stopped sandbox record msb leaves behind (and any orphan `sandboxes\<name>`
   directory a failed create leaves), so the name isn't blocked.
9. **puddle always passes `kind=disk,size=N`** with `--mount-named`, also for an existing volume
   (msb 0.7.6 otherwise treats it as a directory mount).

## Consequences

- **The first sandbox work is "workspace volume lifecycle"** instead of "bind mounts": create (`msb
  volume create --kind disk --size N`) or reuse `ws-<id>`, attach, track the attachment, delete with
  the unpushed-work check (the check runs in the guest, so delete needs a running sandbox or a short
  one started for it), garbage-collect orphaned `volumes\ws-*`, and clean up refused/failed creates.
  Windows path handling mostly drops out. Resizing a volume is not known to be supported by msb; the
  size is set at creation.
- **The IDE attaches into the VM.** VS Code Remote-SSH and JetBrains Gateway open
  `/workspaces/<name>` over `msb ssh`. A guest-local tree means inotify works and the git
  extension is fast. Windows-native tools (Visual Studio, Rider local, Explorer, Windows git GUIs)
  have no access to the live tree until the post-v1 Windows mount feature (4).
- **Backups are `git push`.** Unpushed work exists only inside `disk.raw` under `MSB_HOME`; a
  company's workstation backup doesn't cover it and shouldn't. msb's host helpers can't read files
  inside a disk image, so getting files out needs a running sandbox. The delete check (3) is the
  safety net. Named volumes are not part of msb snapshots or forks.
- **Git credentials come from proxy injection:** clone, fetch and push run in the guest, and the
  proxy adds the credential for github.com and dev.azure.com; the guest only sees a placeholder.
  The first milestone is HTTPS-only and relies on this injection; git over SSH comes later, and
  until then an SSH remote fails with an explicit message.
- **Disk use:** sparse images grow with use and shrink only on trim (7). Each sandbox's root disk
  grows too and can't be trimmed.
- **Crash safety:** filesystem-level consistency after a VMM crash is measured; host power loss is
  not (it depends on msb turning a guest flush into `FlushFileBuffers`).

## Open risks

- **Caches on the root disk can't be trimmed.** npm, NuGet and similar caches in `~` and build
  output outside the workspace live in the sandbox's `upper.ext4`, which grew to 5.4 GB in one
  session and can only be reclaimed by recreating the sandbox. Options (undecided): redirect caches
  onto the workspace volume or a second owned disk, or offer "recreate sandbox" as the reclaim path
  (cheap, since the workspace survives it).
- **Power-loss durability** is untested (see Consequences).
- **Single writer** is only shown for a *running* first sandbox; a second sandbox attaching while
  the first is merely stopped, and whether `msb rm` ever touches a named volume, are untested.
  puddle's own tracking (8) covers this in practice.
- **`core.fsync=committed` cost** on commit-heavy workloads is unmeasured.
- **#1638** has no fix date. It doesn't affect this decision, but blocks any writable host-folder
  feature until fixed (and re-measured: the speed gap stands regardless).

## Alternatives considered

| Option | Why not |
|---|---|
| **virtiofs bind mount of a Windows folder** (default `strict`, `relaxed`, `off`) | Broken by #1638 (renames, git, dotnet build) and 20–26× slower than NTFS regardless; no inotify for host edits; case-insensitive by default; junctions break directories. A writable bind may come back later as an opt-in for read-mostly content, re-measured after #1638 |
| **Owned disk** (`--mount-owned …:kind=disk`) | Same speed, but dies with the sandbox: a rebuild (image bump, config change) loses unpushed work. Right for disposable data such as `/var/lib/docker` |
| **Workspace on the layered rootfs** | Same speed, but dies with the sandbox, ties the work to the image, and can't be trimmed |
| **Owned or named *directory* volume** | virtiofs, the same backend as the bind mount; expected to be as slow (not measured) |
| **Dev Drive / ReFS, or `--mount-disk` of a VHDX on one** | Not tested: creating a Dev Drive needs admin, which the reference workstation and probably most managed machines lack. Would only change how fast the disk image sits on the host, not the decision |
| **WSL2 ext4 shared into the VM** | Puts WSL in the path, which puddle avoids |

## Revisit if

- #1638 ships and a re-measure puts a bind within ~3× of NTFS (unlikely: the round trip dominates).
- msb gains host-side file access to disk volumes, `discard` mounts, or volume resize.
- Users need Windows-native tools on the live tree before the post-v1 Windows mount feature lands.
