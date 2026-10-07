# Rules spec: firewall rules, pending requests, audit

Status: draft for the `puddle-store` rules engine and SQLite store, 2026-10-06.
Written fresh from puddle's own design decisions and threat model. No upstream Huddle rules, store
or test code was used.

Every numbered rule (`R-n`) gets at least one named test in `puddle-store` (`r07_expired_rule_never_matches`, etc.).
Defaults marked *(default)* are reversible choices.

## 1. Model

A **request** is what the proxy asks about: `(sandbox_id, host, port)`. The sandbox id comes from
the route the connection arrived on, never from anything the guest says. `host` is a
normalised name (lowercase, IDNA to ASCII, LDH labels, no trailing dot, at most 253 characters) or
a canonical IP literal (IPv4 dotted quad, IPv6 per RFC 5952). The proxy normalises; the engine only
accepts the normalised type and never parses raw input.

A **rule** says what happens to matching requests:

| Field | Meaning |
|---|---|
| `id` | `i64`, never reused (SQLite `AUTOINCREMENT`) |
| `scope` | `global` or `sandbox` (with `sandbox_id`) |
| `pattern` | `exact` host or IP, or `suffix` (stored as `.example.com`) |
| `effect` | `allow` or `deny` |
| `expires_at` | epoch ms, or `null` for permanent |
| `created_at`, `created_by` | `ts`; actor `cli`, `ui` or `api` |
| `source_pending_id` | the pending row it was approved from, or `null` |

A **pending row** is a request that matched no rule (§3). Rules and pending rows live in SQLite;
the audit (§5) is a SQLite table that is also served as a JSONL stream.

Credential bindings and the local-destination toggles are separate settings, not rules:
a binding never allows a host, and a toggle never allows a destination (R-14).

## 2. Matching

- **R-1 Nothing is pre-decided.** A fresh install has no rules, allow or deny. Every request
  with no matching rule becomes pending (§3); there is no built-in deny list.
- **R-2 Exact rules** match the identical normalised host or IP literal, on any port. Port rules are
  later; the port is still recorded on pending rows and in the audit.
- **R-3 Suffix rules** `.example.com` match every name ending in `.example.com` at any depth, and
  not `example.com` itself *(default)*. Input `*.example.com` is accepted and stored as
  `.example.com`. A suffix rule never matches an IP literal.
- **R-4 A suffix must be longer than a public suffix.** `.com`, `.co.uk` and other entries of the
  bundled public suffix list (ICANN and private sections) are refused as suffix patterns.
- **R-5 Applicable rules** for a request: every non-expired `global` rule plus every non-expired
  `sandbox` rule of that request's sandbox. Another sandbox's rules never apply.
- **R-6 Precedence, most specific wins:** (1) exact beats suffix, and a longer suffix beats a shorter
  one; (2) at equal pattern specificity, `sandbox` beats `global`; (3) at equal scope, `deny` beats
  `allow` *(default)*. So a global deny on `.example.com` can be overridden for one sandbox by a
  sandbox allow on `.example.com` or an exact allow, but never by a broader pattern.
- **R-7 Expiry is checked at decision time.** A rule with `expires_at <= now` (host clock, epoch ms)
  never matches, whether or not the sweeper (§4) has run. The guest's clock plays no part.
- **R-8 Changes apply on the next request**, with no sandbox or proxy restart: a rule change commits
  to SQLite first, then replaces the engine's in-memory rule set atomically. A decision never sees a
  half-applied change. Connections already open when a rule is deleted or expires are not cut
  *(default)*; the next connection is decided anew.
- **R-9 The decision says how it matched:** `allow { rule_id, pattern }`, `deny { rule_id }` or
  `pending { pending_id, outcome }` (`outcome`: `new`, `repeat`, `suppressed`). The proxy needs the
  pattern kind for R-14.

## 3. Pending requests

States: `requested → allowed | denied | expired`. The three end states are final.

- **R-10 Unmatched requests are denied and recorded.** The proxy answers 403 at once
  (fail fast, the client retries); the row keeps `first_seen`/`last_seen` so
  parking the connection can be added later without a schema change. The name is never resolved
  before a rule allows it.
- **R-11 Dedupe on `(sandbox_id, host, port)`:** at most one `requested` row per key (a partial unique
  index). A repeat updates `last_seen` and increments `attempts` on the existing row; it creates
  nothing. A request after the row ended (for example the allow it created later expired) opens a
  new row with a new id.
- **R-12 Pending rows are immutable:** `id`, `sandbox_id`, `host`, `port` and
  `first_seen` never change after insert; ids are never reused. Only `last_seen`, `attempts`,
  `state`, `decided_at`, `decided_by` and `rule_id` change, and `state` only along the arrows above.
- **R-13 Per-sandbox rate limit on new rows:** a token bucket per sandbox, 60 new rows
  burst, refill 1 per second *(default)*, plus at most 500 open rows per sandbox *(default)*. Over
  the limit the request is still denied, no row is written, and the sandbox's `suppressed` counter
  goes up. One `pending_suppressed` audit record carries the count when suppression starts and
  every 60 s while it lasts; the inbox shows "N requests from <sandbox> suppressed". Repeats of an
  open row (R-11) never consume tokens.
- **R-14 Local destinations** (the proxy applies this after resolving an allowed name; the engine supplies
  the match): an address in a local category with its toggle off is blocked and the block names
  the toggle, with no pending row. With the toggle on, only an `exact` allow
  counts: of the name, or of the resolved address itself (an exact IP rule admits that address,
  and only it). A suffix allow is treated as no match, and if no address is admitted the request
  goes pending for the exact name, unless the "wildcards reach local addresses"
  setting is on (global default off, per-sandbox override *(default)*). The IP check only looks
  up rules (`Policy::lookup`); it never writes a pending row for the address. puddle's own
  endpoints are blocked whatever rules or toggles say, and never become pending.
  *Changed 2026-10-06: the exact-IP case was added, following the principle that a local destination
  needs an exact name or IP entry; before, only an exact name rule or an approval counted.*
- **R-27 An exact IP deny wins for a resolved address** (the proxy applies this to every address an
  allowed name resolves to, before R-14). The proxy looks up each address's own rules
  (`Policy::lookup`, R-5 to R-7 as for a request to that literal): if they deny it, the address is
  never used, whatever allows the name (exact, suffix, or an approval) and whether it is local or
  public. The remaining addresses go on to R-14. If every address is denied, the request is denied
  with the IP rule's id (`x-puddle-rule`, and `rule_id` with `resolved_ip` in the `connection`
  record); no pending row is written, because approving the name can't change it. A failed lookup
  refuses the request (fail closed). A request for an IP literal was already decided as that
  address. *(default)*: an address's own rules use R-6 precedence, so a sandbox allow of the
  address beats a global deny of it. Numbered R-27 to keep the other numbers (and their test
  names) stable. *Added 2026-10-06: before, an IP deny was checked only on the wildcard
  path, so an exact name allow or an approval reached a denied address (firewall model,
  2026-10-04: false allows are very bad).*
- **R-15 Approve and deny** take a row id and four choices: effect (`allow`/`deny`), scope (`sandbox`,
  the default, or `global`), pattern (`exact`, the default, or a suffix of the row's host that passes
  R-4) and expiry (permanent, the default, or a duration). This covers the inbox's four outcomes
  (allow/deny × this sandbox/everyone). Defaults are never widened implicitly.
- **R-16 A decision is one transaction:** create the rule, set the row to `allowed`/`denied` with
  `rule_id`, `decided_at` and `decided_by`, and close every other `requested` row the new rule now
  decides (same sandbox for a sandbox rule, any sandbox for a global one) the same way.
- **R-17 Stale ids are refused.** Approving or denying an unknown id or a row not in `requested`
  fails with an error naming the row's current state; nothing changes. A successful call returns
  the row as decided (sandbox, host, port) and the rule created, so the CLI and UI can echo exactly
  what was approved.
- **R-18 The inbox groups by registrable domain** (public suffix list, as R-4) for display; grouping
  is derived, not stored, and never decides anything.

## 4. Sweeper

One background task, every 60 s *(default)* and at startup:

- **R-19** deletes rules with `expires_at <= now` and writes a `rule_expired` audit record holding
  the whole rule. Correctness never depends on it (R-7).
- **R-20** moves `requested` rows whose `last_seen` is older than 7 days *(default)* to `expired`.
- **R-21** on sandbox deletion (not stop), deletes that sandbox's rules (`rule_deleted`, reason
  `sandbox_deleted`) and expires its open rows, in the same transaction as the deletion.
- **R-22** enforces the audit cap (R-26).

Sweeper work never holds a lock that a decision waits on for more than one short transaction.

## 5. Audit

Every decision, rule change and pending change is one record: a row in the SQLite `audit` table,
readable as JSONL (one record per line).

- **R-23 Serialised with `serde_json` only**, from one internally tagged enum
  (`"type": "..."`), per ADR 0002: `snake_case` fields, `ts` in epoch ms, `null` always written,
  never `untagged`, additive changes only. Control characters in any string come out escaped, so
  every line parses with `jq`.
- **R-24 Record types** in `puddle-store`: `connection` (written by the proxy: `sandbox_id`, `host`, `port`,
  `resolved_ip`, `decision` (`allow`, `deny`, `pending`, `blocked`), `reason` (`rule`, `no_rule`,
  `toggle:<category>`, `puddle_endpoint`, `ssh_unsupported`, `local_address`,
  `policy_unavailable`, `suppressed`, ...), `rule_id`, `pending_id`, `binding_id`, `injected`,
  `method` and `path` on terminated hosts, plain-HTTP requests and `CONNECT` tunnels that carry
  plain HTTP/1.x only, `bytes_up`, `bytes_down`), `pending_created`, `pending_decided`, `pending_expired`,
  `pending_suppressed` (`sandbox_id`, `count`), `rule_created`, `rule_updated`, `rule_deleted`,
  `rule_expired` (with the full rule), `audit_trimmed` (`deleted_records`, `oldest_ts_kept`).
  The proxy writes one `connection` record per request whose destination it parsed, when the
  connection ends; a request refused before that (bad request, head too large or too slow, the
  sandbox over its connection limit) has no destination and only goes to the log. `resolved_ip`
  is the address connected to (`null` if none was), and the bytes are counted on the guest side,
  proxy responses included.
  A `CONNECT` tunnel is decided like any request (rules see `(sandbox, host, port)`, R-2), so
  `CONNECT host:80` and `GET http://host/` get the same decision and pending row. Node `fetch` and
  Yarn Berry send `http://` URLs that way. When a tunnel's first bytes are an HTTP/1.x request line,
  its record carries that request's `method` and `path` (first request only); the bytes are
  relayed unchanged. *Added 2026-10-06.*
  `upstream` names the company-proxy hop that carried the connection (`DIRECT` or `PROXY host:port`,
  never credentials; `null` when no upstream route is configured or nothing connected), and when
  it is a proxy hop `resolved_ip` is the address sent to the proxy, or `null` if the proxy was told
  the name (or this host could not resolve it). *Added 2026-10-07 (additive).*
- **R-25 No secrets.** Never header values, credential material, query strings or request bodies;
  credentials appear only as `binding_id` and `injected: true|false`. Every audit struct has a test
  that serialises it with canary values in every secret-bearing input and asserts the canary is
  absent.
- **R-26 Size caps.** One line is at most 4 KiB: `path` is cut to 1 KiB *(default)* with
  `path_truncated: true`, and any other oversize string field is cut the same way. Total audit is
  capped at 256 MiB *(default)*; the sweeper deletes the oldest records first and writes one
  `audit_trimmed` record per trim. Per sandbox, `connection` records are limited to 200 per second
  *(default)*; the excess is counted and written as one `connection` record with
  `reason: suppressed` and a `count` per second.

- **R-28 Reading the audit with filters.** The API filters on the server, on stored columns and
  indexes (never by parsing JSON): `sandbox`, `type`, `outcome`, `host_contains` (case-folded
  substring), `from` (inclusive) and `to` (exclusive) as epoch ms. All set filters must match.
  `host` is the record's host, or a rule record's pattern. `outcome` (`allow`, `deny`, `pending`,
  `blocked`, `expired`) exists for `connection` (its `decision`), `pending_created` (`pending`),
  `pending_decided` (`allow` or `deny`) and `pending_expired` (`expired`); every other record has
  none and never matches an `outcome` filter. Pages are at most 500 records: newest first, paged
  back with `before`, or oldest first from `after` to follow the tail.
- **R-29 Events.** After each commit the store emits, per change: `pending_opened` (a new open
  row), `pending_updated` (a repeat: `attempts`, `last_seen`), `pending_closed` (decided by a user
  or a rule, or expired: `state`, `rule_id`), `suppression_changed` (R-13: when it starts or ends,
  and at most twice a second while the count grows), `rules_changed` (any rule created, changed,
  deleted or expired) and `audit_appended` (once per commit that wrote audit records, with the
  newest id). Events carry ids and counts, not decisions: a client that missed some refetches.
  A failed change emits nothing.

## 6. Out of scope here

The AI judge (no field or placeholder until its flow is designed), rule sets the user can
enable (v1; they will be a third scope), path rules (after v1), port rules, and the
"Dangerous settings" unblock of puddle's endpoints (later). Address classification, name
normalisation and the 403 body belong to the proxy and `puddle-netpolicy`; the API and CLI shape of R-15
to `puddle-api` and `puddle`.
