# 0004 — API contract: OpenAPI-first, not type-only

Date: 2026-08-20
Status: accepted
Amends: [0002](0002-wire-format-and-types.md) and [0003](0003-product-frontend.md) — both named
`ts-rs`. That was the right tool for the problem as stated then (an internal boundary, types only,
added late). With Svelte decided, TypeScript is permanent and the API has more consumers than the
UI, so the problem changed.

## Why the earlier pick no longer fits

`ts-rs` generates **payload types**. It says nothing about *endpoints*: path, method, query
parameters, status codes, which request type belongs to which response type. With it you still
hand-write `fetch('/api/rules/' + id, {method:'POST'})` and a typo, a renamed route or a changed verb
is a runtime 404 in a webview rather than a compile error. At five screens added later, that was
acceptable. For eight to twelve screens, a CLI, browser mode, automation, and a plausible extensions
API later, the endpoint surface *is* the contract, and it should be checked.

There is also a one-generator rule worth respecting: once a spec exists, `ts-rs` becomes a second
generator of the same truth.

## Decision

**OpenAPI 3.1, generated from the Rust handlers, consumed as a typed client in Svelte.**

- **Server**: `utoipa` 5.5 for schemas and path annotations, wired through **`utoipa-axum`'s
  `OpenApiRouter`** so routes and spec are registered together and cannot drift apart. Spec served
  at `/api/openapi.json`; `utoipa-scalar` gives a browsable API page in dev builds.
- **Client**: `openapi-typescript` 7.13 for the types, `openapi-fetch` 0.17 (~6 kB) for the client.
  Wrong path, wrong method, missing body field, misread response — all compile errors, no runtime
  layer to speak of.
- **CI gate**: regenerate the spec and the TS types, then `git diff --exit-code`. Both artefacts are
  committed.
- **`ts-rs` is out.** One generator.

### The SSE stream is the exception

OpenAPI describes `text/event-stream` badly. So: the event union is declared as OpenAPI **component
schemas** (same derives, same types, appearing in the same generated `.d.ts`), and the transport is a
hand-written typed `EventSource` wrapper of roughly thirty lines that switches on the ADR 0002
discriminator. Types generated once; only the wrapper is hand-written, and it has no schema of its
own to drift.

### Two conventions added to ADR 0002

- **No `#[serde(flatten)]` in wire types.** It produces schemas that generators mangle, and it is the
  single most common source of OpenAPI-versus-reality mismatches.
- **Every request and response body is a named struct** — no anonymous tuples, no bare maps — so the
  spec has stable component names and the generated TypeScript has stable type names.
- Inbound request types get `#[serde(deny_unknown_fields)]`, so the spec is enforced rather than
  merely published. That matters the day an extension or a script is the caller.

## One thing to verify at implementation time, not now

`utoipa` core is actively maintained (5.5.0, May 2026, ~13M recent downloads), but **`utoipa-axum`
is at 0.2.0 from January 2025** — plausibly just stable, plausibly stale. Before committing, check
that it supports the axum version we pin. If it does not, use **`aide` 0.15.1** (April 2026, axum-
native, same OpenAPI-first shape) and keep everything else in this ADR unchanged. That is a
thirty-minute check against a real `Cargo.toml`, not a decision to argue in a document.

## Alternatives considered

- **`ts-rs` plus a hand-written client** — cheaper by roughly half a day, buys payload types only.
  Rejected above.
- **`specta` 2** — would give types and OpenAPI from one derive, but its latest stable is 1.0.5 while
  the 2.x line has been in pre-release a long time. Not a contract-layer dependency today.
- **`schemars` → JSON Schema → TS + runtime validation** — the right answer if the *client* ever has
  to validate at runtime. It does not: the server is the same binary on the same machine. Keep
  validation server-side via `deny_unknown_fields`.
- **`orval`** instead of `openapi-fetch` — generates hooks and heavier clients aimed at React Query;
  more machinery than a five-screen-to-twelve-screen app with SSE needs.
- **protobuf / gRPC** — still no, for the reasons in ADR 0002.

## The full options ledger

For the record, including options weighed but not previously written down. Everything here was
judged against the same requirements: Rust owns the domain, TypeScript consumes it, a CLI and
automation consume the same surface, the audit trail must stay human-inspectable, and an extensions
API is plausible later.

| Option | Verdict |
|---|---|
| `ts-rs` 12.0.1 | Chosen, then retired — payload types only, no endpoint checking |
| `typeshare` 1.13.4 | Out — separate installed CLI, syntactic parsing, least active of the three |
| `specta` 2 | Out — latest stable is 1.0.5 while the 2.x line has been pre-release for a long time |
| `schemars` 1.2.2 → JSON Schema → TS | Held in reserve — the answer if the client ever needs runtime validation, or if a schema artefact must be published separately from an API spec |
| **`utoipa` 5.5 → OpenAPI → `openapi-typescript` + `openapi-fetch`** | **Chosen** |
| `aide` 0.15.1 | Standby — same shape, axum-native, and the fallback if `utoipa-axum` does not support our pinned axum |
| `orval` 8.24 | Out — generates React-Query-shaped clients; more machinery than needed |
| protobuf / gRPC (+ Connect, grpc-web, `protobuf-es`) | Out — see ADR 0002: browsers need a shim, binary frames fight an SSE text stream, the audit log loses `curl`/`grep` inspectability in a security tool, and `protoc`/`buf` re-enters a build we kept clean |
| Cap'n Proto, FlatBuffers, MessagePack, CBOR | Out for the same reasons, with even less tooling on the TS side. Payload size is irrelevant on loopback, which is the only thing they would buy |
| **GraphQL (`async-graphql` 7.2.1 + graphql-codegen)** | **The strongest alternative, and not previously written down.** It would solve types, endpoints and the live stream in one: subscriptions could replace SSE, and TS codegen for GraphQL is excellent. Out because it is heavy for ~15 endpoints, adds a query planner and its own security surface (query depth and complexity limits) to a security tool, and makes the audit/inspection story worse — one opaque POST endpoint instead of greppable paths. Revisit only if several clients with genuinely divergent data needs appear |
| **TypeSpec 1.15 (IDL-first, emitting OpenAPI)** | **The honest version of "define the DTOs outside either language"** — a real IDL without protobuf's wire format, and also not previously written down. Out because we own both ends: Rust-first generation is less ceremony and cannot drift from the handlers, whereas an IDL adds a third artefact to keep in sync. It becomes correct the day a *third party* owns the contract |
| **Tauri IPC commands + `tauri-specta` 1.0.2** | Typed bindings for free, no HTTP layer — but it makes the API Tauri-shaped, so browser mode and the CLI lose the surface they share with the UI. Out on architecture, not tooling: the API is axum on loopback precisely so those three consumers see one contract |
| Zod-first (TypeScript as source of truth, generate Rust) | Out — inverts ownership; the domain lives in Rust |
| Hand-written DTOs, reviewed by humans | The baseline this all argues against; drift is found by users, not by CI |

## Consequences

- The API work grows by about a day: annotations on roughly fifteen endpoints, codegen wiring, the
  CI gate. Call it **1.5–2 days** of contract work against `ts-rs`'s ~1.
- The frontend gets endpoint-level type safety, which is the class of bug most likely to survive
  review in a UI that mostly makes HTTP calls.
- A published, versioned spec exists from the start, so an extensions API or a central policy feed
  does not need a retrofit — and neither needs protobuf to be well specified.
- ADR 0002's wire conventions are unchanged and now have three more.
