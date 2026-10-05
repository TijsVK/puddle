# 0002 — Wire format and type generation

Date: 2026-08-20
Status: accepted; **amended by [0003](0003-product-frontend.md) and
[0004](0004-api-contract.md)** — `ts-rs` is superseded by an OpenAPI-first contract; the wire
conventions below stand and 0004 adds three more. Also amended by 0003 — the wire conventions stand, but
"no type tooling needed" described the MWE spike only. The product has a TypeScript consumer, so
`ts-rs` is in from the start.
Context: [ADR 0001](0001-frontend-stack.md),
Svelte vs Dioxus, section "Can a schema neutralise the shared-struct advantage" (workspace:
`docs/plan/2026-08-svelte-vs-dioxus.md`)

## Decision

**Types: `ts-rs`** (v12.0.1, updated 2026-01-31, ~4.6M recent downloads), added the day a JavaScript
client exists — not before. Rust stays the single source of truth; generated `.ts` is checked in and
CI fails if regeneration changes it.

**No protobuf, no gRPC.** JSON over HTTP and SSE.

**The wire conventions below are fixed now**, in the MWE, even though no codegen tool is installed
yet. The SSE and audit formats are being designed this month; the conventions are the part that is
expensive to change later, and the PoC's JSONL audit already follows most of them.

### When is a type generator needed at all?

Tauri does not imply TypeScript. What decides this is *who parses the payload*, not whether the app
is a desktop window:

| UI approach | Cross-language boundary? | Type tooling |
|---|---|---|
| **Server-rendered HTML from axum** (the MWE, in a Tauri webview) | No — the HTML is built in Rust from Rust structs; the webview only displays it | **None.** There is nothing to generate |
| Server-rendered + a JSON endpoint that vanilla JS reads | Yes, but informal and tiny | Optional; hand-written and reviewed is honest at this size |
| Svelte SPA | Yes — TypeScript parses JSON | **`ts-rs`** |
| Dioxus SPA | No — the same Rust structs render the UI | **None** |

So the desktop app needs no type generation *as a desktop app*. It needs it only if a TypeScript
consumer appears, which under ADR 0001 is a deliberate later choice.

**Then why fix JSON conventions now?** Because the UI is not the only consumer, and the other two
exist from day one:

- **the audit log** — the PoC already emits JSON lines, and operators, scripts and future exports
  read them. That is a public contract whether or not a frontend consumes it;
- **the REST endpoints** — a CLI, automation and browser mode all want them, and they outlive any
  particular UI.

**One MWE choice this exposes:** the SSE stream should carry **HTML fragments**, not JSON, for lists
and rows. The client then needs no schema, no parsing and no types, which is what makes "no type
tooling" genuinely true rather than an accounting trick. Keep JSON for the audit log and for REST
responses, where the consumer is a script rather than a webview.

### Wire conventions

| Rule | Why |
|---|---|
| **`snake_case` field names**, no `rename_all` | Matches Rust and matches the audit lines the PoC already emits (`bytes_up`, `bytes_down`, `ts`). One less transform, one less place for a rename to silently break a consumer |
| **Event stream is one internally-tagged enum**: `#[serde(tag = "type", rename_all = "snake_case")]` | Gives TypeScript a discriminated union the compiler can check exhaustively. `switch (e.type)` beats guessing |
| **Unit enums serialise as `snake_case` strings** (`allow`, `deny`, `requested`) | Readable in the audit log; no integer-to-meaning lookup |
| **Never `#[serde(untagged)]`** | Silent misparsing; the failure mode is a wrong branch rather than an error |
| **Timestamps: epoch milliseconds as `u64`**, field `ts` | ~1.7 × 10¹² is far below JS's 2^53 limit, so no precision trap, and it sorts and diffs trivially. RFC 3339 only where a human reads it directly |
| **IDs: `i64` row ids are fine; anything opaque is a `String`** | Row ids stay well under 2^53. UUIDs, tokens and sandbox ids are strings so they can never be coerced to a number |
| **Always serialise `null`; no `skip_serializing_if`** | TypeScript sees a consistent `T \| null` instead of "absent sometimes, null other times". Absence should mean "this version does not have the field", nothing else |
| **Additive changes only on the event stream**, new fields get `#[serde(default)]` | An old UI in a webview that has not reloaded must not break on a new field |
| **Wire types live in one `wire` module** | The contract is a deliberate artefact, not whatever the domain structs happen to look like this week |

Start with one set of types where domain and wire agree, and split a wire type out the moment it
would otherwise leak internals or force a domain change for presentation's sake. Splitting early
everywhere buys mapping code we do not need at five screens.

### Pipeline, when it arrives

`#[derive(TS)]` + `#[ts(export)]` on the `wire` module, exported into the frontend's source tree and
committed; a `cargo xtask codegen` wrapper; CI runs it and then `git diff --exit-code`. Drift becomes
a red build rather than a runtime `undefined`.

## Alternatives considered

- **`specta`** — attractive because `specta_openapi` could emit OpenAPI from the same types, but the
  crate's latest *stable* release is 1.0.5 while the 2.x line people actually want has been in
  pre-release for a long time. Not the dependency to pick for a contract layer right now.
- **`typeshare`** — fine tool, but it needs a separate installed CLI, parses syntactically rather
  than through the type system, and is less active (1.13.4, Dec 2025) than ts-rs.
- **`schemars`** (1.2.2, heavily used) → JSON Schema → TS — an extra hop for the internal boundary,
  but **this is the right pick if we ever want runtime validation or a published schema artefact**,
  and it composes with the conventions above.
- **`utoipa`** (5.5.0) → OpenAPI → `openapi-typescript` — the answer for an *external, documented*
  API: extensions, a central policy feed, third-party clients. Not needed for our own UI.
- **protobuf / gRPC** — rejected in the comparison doc: browsers need Connect or grpc-web,
  binary frames fight an SSE text stream, it costs the audit log its `curl`/`grep` inspectability in
  a security tool, it re-adds `protoc`/`buf` to a build we just kept Node out of, and proto3 brings
  its own friction (integer enums, no required fields, `int64` as a string in protobuf-JSON anyway).

## Consequences

- Nothing to install for the MWE; the server-rendered UI has no DTO layer, and the SSE stream carries
  HTML fragments so the client needs no schema at all.
- The conventions apply immediately to the audit rows, the SSE events and the REST responses, so the
  first JS client is a codegen step rather than a redesign.
- If Dioxus is ever chosen instead of Svelte, this ADR costs nothing: the `wire` module is already
  the shared type set, and the codegen step simply never gets added.
