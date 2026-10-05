# 0001 — Frontend stack: no Angular; server-rendered first

Date: 2026-08-20
Status: accepted; **amended by [0003](0003-product-frontend.md)** — the "defer the SPA question"
clause argued from the MWE's shape rather than the product's, and 0003 replaces it with Svelte 5 for
the product. The "Angular is out" decision stands unchanged. **Since 2026-10-06 (D-54)** the code-port
list in "Consequences" no longer holds: nothing is copied or reimplemented from upstream (ADR 0003's
amendment of that date).
Context: workspace: `docs/plan/2026-08-frontend-evaluation.md`

## Decision

1. **Angular is out**, for the MWE and for the eventual SPA. Upstream's Angular portal is not
   carried over and is not the target of a port.
2. **The MWE frontend is server-rendered** from axum: five screens (workspaces, pending requests,
   rules, audit, workspace detail), SSE for live updates, a few hundred lines of vanilla JS.
   `xterm.js` loads as a plain `<script>` if the in-portal terminal is wanted.
3. **The SPA question stays open**, and may never need answering. If the server-rendered UI proves
   insufficient, the default is **Svelte 5**, with **Dioxus 0.7** as a deliberate bet where one
   language and a Node-free build outweigh pre-1.0 churn — compared in depth in
   workspace: `docs/plan/2026-08-svelte-vs-dioxus.md`, and settled by
   building the pending-request screen twice (half a day each) rather than by argument. React and
   Leptos are out: React adds nothing over Svelte here, Leptos is web-first where this is a desktop
   app.

## Why

- The UI is five screens of tables, buttons and a live list. Every hard problem in this product —
  proxy, policy engine, sandbox lifecycle, SSH attach — is in Rust.
- Angular means adding Node, npm and the Angular CLI to the CI of a repo that builds with `cargo`
  alone, to render tables.
- The "we already have Angular components" argument was worth 1–2 days of transfer, not a toolchain
  commitment — and upstream is zone-based while Angular 21 is zoneless-by-default, so the reactive
  plumbing is rewritten no matter the target.
- Deciding the framework *before* the event model exists is deciding without information. Rendering
  server-side defers it at a cost of 2–3 days, which is less than the strip (6–9) or a fresh SPA
  (5–7) would have cost anyway.

## Consequences

- **The code-port list shrinks.** Only framework-free material copies: `path-allowlist.util.ts`
  (52), `pie-menu.model.ts` (29), `icons.ts` (45), the two pipes' logic (~40) and extracted theme
  tokens (~150) — roughly **320 LOC**. The Angular-bound components (`container-terminal` 301,
  `pie-menu` 280, `path-allowlist` 156, `confirm-modal` 39 ≈ **780 LOC**) become reimplementations
  guided by the originals, not copies. The interaction design carries over in full as the lessons in
  the evaluation doc; that was always the valuable part.
- No Node in the build for the MWE. Keep it that way for as long as it holds.
- The best outcome is that the server-rendered UI is simply enough, and no SPA is ever added. Treat
  that as the expected case, not a fallback.
- MWE frontend effort: 2–3 days (was 5–7 for a fresh SPA). MWE total: 19–29 engineer-days.

## Revisit if

A second frontend-fluent developer joins and will own the UI long-term, **or** huddle-next has to
ship the same portal to central/server deployments as well as the desktop app — at which point fleet
views return and the UI is no longer five screens. Reopening then is a new decision with new
information, not a reversal of this one.
