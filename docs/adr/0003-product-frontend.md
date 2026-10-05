# 0003 — Product frontend: Svelte 5, decided on the product's requirements

Date: 2026-08-20
Status: accepted; **amended by [0004](0004-api-contract.md)** — the Svelte decision stands, but the
contract tool is OpenAPI-first (utoipa → openapi-typescript/openapi-fetch), not `ts-rs`.
**Amended 2026-10-05 (D-48)**: decision 3 ("the MWE gets no UI at all") no longer holds; the MWE now
includes the product UI. See [the amendment](#amendment-2026-10-05-the-mwe-includes-the-product-ui-d-48)
at the end. The text above it is left as written on 2026-08-20.
**Amended 2026-10-06 (D-54)**: no upstream code is copied or reimplemented; the ~320 copied and
~780 reimplemented LOC in "Consequences" are dropped, the nine lessons stand. See
[the amendment](#amendment-2026-10-06-written-fresh-no-huddle-material-d-54).
Amends: [0001](0001-frontend-stack.md) (the "defer the SPA question" part),
[0002](0002-wire-format-and-types.md) (the "no type tooling needed" reading)

## The correction that produced this ADR

ADRs 0001 and 0002 argued from the MWE: five screens, server-rendered, therefore no framework
decision and no type generation. That is backwards. **The MWE is a spike that validates plumbing —
microVM lifecycle, the vsock chokepoint, policy enforcement, SSH attach. It is not a small version
of the product and it sets no precedent.** Decisions about the shipped application have to be
argued from the shipped application's requirements.

Rule going forward: if a claim in a design document depends on the MWE's shape, it is not a design
decision, it is a spike detail.

## What the product's frontend actually has to carry

Not five screens. Taking upstream's real surface, minus what the runtime boundary deletes, plus what
this architecture adds:

- **Workspaces**: list and per-workspace detail with tabs; create/start/stop; **one-click attach**,
  which is the single most-used action in the product.
- **Approvals**: a pending inbox with the four-outcome interaction (allow/deny × this
  workspace/everyone), plus allow-exact-path once path rules land. Live, and it must not be a page
  someone has to be looking at.
- **Firewall**: global and per-workspace rules, permanent and time-bound, path-mode subpaths —
  tables with filtering, editing and expiry.
- **Audit / network log**: a long, growing, filterable, searchable stream. This is the product's
  trust surface, so it needs real table behaviour, not a `<pre>` block.
- **Terminal**: xterm, per workspace.
- **Settings**: bind mounts (upstream's folder mappings), images, runtime pin, theme.
- **Snapshots** and **extensions**: later, but they are screens, not footnotes.

That is eight to twelve screens with live data, filters, forms, modals and a design language to
maintain — an application, and it will be maintained for years. Server-rendered HTML with a
sprinkle of vanilla JS is the wrong tool for that, and "we might never need an SPA" was an artefact
of measuring the spike instead of the product.

## Decision

1. **The product frontend is a Svelte 5 SPA**, served by axum (and by Tauri in the desktop shell).
   Reasoning is in the comparison (workspace: `docs/plan/2026-08-svelte-vs-dioxus.md`); at product scale every
   factor that favoured Svelte gets stronger — components you do not write, a real testing path, a
   fast dev loop, no pre-1.0 churn in the layer touched daily — while Dioxus's advantages (one
   language, no Node, shared structs) stay the same size or shrink, because a generated contract
   closes the type gap for a day or two of setup ([ADR 0004](0004-api-contract.md)).
2. **A generated contract is in from the start**, with the wire conventions of ADR 0002, generated
   output committed, and a CI diff gate. It is not deferred: there is a TypeScript consumer by
   definition now. [ADR 0004](0004-api-contract.md) picks the tool — OpenAPI-first rather than
   `ts-rs`, because the endpoint surface needs checking too, not just payload shapes.
3. **The MWE gets no UI at all.** Validate approve/deny with `huddle approve <id>` / `huddle deny
   <id>` on the CLI plus the JSONL audit stream. That is honest about what the spike is for, it
   removes 2–3 days of throwaway UI, and it makes it impossible for spike scaffolding to become the
   product's frontend by inertia.
4. **Dioxus stays recorded as the road not taken**, with its trigger: if this product ever has to
   run without a Node toolchain in the build — an air-gapped or vendor-restricted build environment
   — that is the reason to revisit, not developer preference.

## Consequences

- **Effort moves, and grows.** The MWE frontend line item drops from 2–3 days to **0** (a CLI
  subcommand, ~half a day inside W7). The product frontend becomes its own budgeted piece of work
  after the MWE: realistically **12–20 engineer-days** for eight to twelve screens done properly,
  reusing the ~320 LOC of copied material and the nine interaction lessons. The earlier "5–7 days
  for a fresh SPA" figure was for the spike's five screens and should not be quoted for the product.
- Node and Vite return to the build, for the frontend only. The Rust binary still builds with
  `cargo`; CI gains a frontend job.
- ADR 0002's conventions apply unchanged, and its "no tooling needed" table now describes only the
  spike.
- The design work that was already done stands: nothing about upstream's portal becomes worth
  carrying, and the port list (~320 LOC copied, ~780 reimplemented, nine lessons) is unaffected by
  which framework renders it.

## Amendment 2026-10-05: the MWE includes the product UI (D-48)

The user decided that the MWE isn't called done or drivable until it is somewhat usable (D-48,
workspace: `work/decisions.md`, 2026-10-05). So the MWE now includes the product UI (this ADR's Svelte 5 SPA,
with D-14's first-UI items), the Tauri shell with MSI and signing, browser VS Code in a
puddle-owned Tauri window, and an explicit "SSH not supported yet" message
(MWE plan, workspace: `docs/plan/2026-08-mwe-approve-deny.md`; T-064).

What changes here:

- **Decision 3 is superseded.** The MWE has a UI, and it is the product's own frontend: decision 1
  (Svelte 5 SPA, served by axum and by Tauri) and decision 2 (generated contract, ADR 0004) apply
  to it unchanged. The CLI `approve`/`deny` and the JSONL audit stream stay, as a second consumer
  and for scripted tests.
- **"The MWE is a spike that sets no precedent" no longer describes the MWE.** It is the first
  usable cut of the product, built in the product's architecture. The rule of this ADR still
  holds, and now matters more: design claims are argued from the shipped application's
  requirements, never from what was quickest to get the MWE running. The incremental order keeps
  a CLI-driven plumbing stage first, but that stage is not called the MWE.
- **The risk decision 3 guarded against**, spike scaffolding becoming the product frontend by
  inertia, is handled by building no scaffolding UI at all: no server-rendered or throwaway screens
  at any stage.
- **Effort.** The 12–20 engineer-days moved from "after the MWE" into the MWE (W5), plus the D-14
  backend; the MWE total rose from 47–68½ to 69½–104½ human-days (MWE plan §2).

Unchanged: decision 4 (Dioxus as the road not taken, with its trigger) and the screen list above;
snapshots and extensions are still later (after v1 and only if asked, D-48).

## Amendment 2026-10-06: written fresh, no Huddle material (D-54)

puddle is the user's personal project, licensed GPL-3.0-or-later by its own choice, and takes only
ideas from Huddle (D-54, workspace: `work/decisions.md`, 2026-10-06). Translating code counts as modifying it
under copyright law, so a Svelte reimplementation made with the Angular original open beside it
would still derive from Huddle.

What changes here:

- **The port list is dropped.** The ~320 LOC "copied material" (path-allowlist util, pie-menu
  model, icons, two pipes, theme tokens) and the ~780 LOC "reimplemented" components
  (`container-terminal`, `pie-menu`, `path-allowlist`, `confirm-modal`) are not used. Instead: own
  theme tokens, an MIT/ISC icon set such as Lucide, `Intl`-based formatting, and the pie menu and
  confirm modal built from the interaction lessons; the logo is puddle's own.
- **Clean-room rule:** whoever builds these screens (human or agent) does not open upstream's
  Angular components, CSS or icon files for them.
- **The nine interaction lessons stand.** They are ideas, written in our own words.
- **Effort.** The SPA goes from 12–20 to 13–21½ days; the MWE total from 76½–115 to 78½–118½
  human-days (MWE plan §2, which also moves W3 to its own rules spec and tests).
