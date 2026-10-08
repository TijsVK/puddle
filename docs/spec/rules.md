# Rules spec: firewall rules, pending requests, audit

Status: draft for the `puddle-store` rules engine and SQLite store, 2026-10-06.
Written fresh from puddle's own design decisions and threat model. No upstream Huddle rules, store
or test code was used.

Every numbered rule (`R-n`) gets at least one named test in `puddle-store` (`r07_expired_rule_never_matches`, etc.).
Defaults marked *(default)* are reversible choices.

## 1. Model

A **request** is what the proxy asks about: `(workspace_id, host, port)`. The workspace id comes from
the route the connection arrived on, never from anything the guest says. `host` is a
normalised name (lowercase, IDNA to ASCII, LDH labels, no trailing dot, at most 253 characters) or
a canonical IP literal (IPv4 dotted quad, IPv6 per RFC 5952). The proxy normalises; the engine only
accepts the normalised type and never parses raw input.

A **rule** says what happens to matching requests:

| Field | Meaning |
|---|---|
| `id` | `i64`, never reused (SQLite `AUTOINCREMENT`) |
| `scope` | `global` or `workspace` (with `workspace_id`) |
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
  with no matching rule becomes pending (§3); there is no built-in deny list. The built-in rule
  sets ship switched off (R-36); the one thing puddle allows by itself is the short System managed
  list, derived from the user's own setup choices and shown with a reason for every host
  (R-40, R-41). *Note added 2026-10-08.*
- **R-2 Exact rules** match the identical normalised host or IP literal, on any port. Port rules are
  later; the port is still recorded on pending rows and in the audit.
- **R-3 Suffix rules** `.example.com` match every name ending in `.example.com` at any depth, and
  not `example.com` itself *(default)*. Input `*.example.com` is accepted and stored as
  `.example.com`. A suffix rule never matches an IP literal.
- **R-4 A suffix must be longer than a public suffix.** `.com`, `.co.uk` and other entries of the
  bundled public suffix list (ICANN and private sections) are refused as suffix patterns.
- **R-5 Applicable rules** for a request: every non-expired `global` rule plus every non-expired
  `workspace` rule of that request's workspace. Another workspace's rules never apply.
- **R-6 Precedence, most specific wins:** (1) exact beats suffix, and a longer suffix beats a shorter
  one; (2) at equal pattern specificity, `workspace` beats `global`; (3) at equal scope, `deny` beats
  `allow` *(default)*. So a global deny on `.example.com` can be overridden for one workspace by a
  workspace allow on `.example.com` or an exact allow, but never by a broader pattern.
- **R-7 Expiry is checked at decision time.** A rule with `expires_at <= now` (host clock, epoch ms)
  never matches, whether or not the sweeper (§4) has run. The guest's clock plays no part.
- **R-8 Changes apply on the next request**, with no workspace or proxy restart: a rule change commits
  to SQLite first, then replaces the engine's in-memory rule set atomically. A decision never sees a
  half-applied change. Connections already open when a rule is deleted or expires are not cut
  *(default)*; the next connection is decided anew.
- **R-9 The decision says how it matched:** `allow { rule_id, pattern }`, `deny { rule_id }` or
  `pending { pending_id, outcome }` (`outcome`: `new`, `repeat`, `suppressed`). The proxy needs the
  pattern kind for R-14. A rule set's entry decides as `set_allow { set, rule_id?, pattern }` or
  `set_deny { set, rule_id, pattern }` (§7).

## 3. Pending requests

States: `requested → allowed | denied | expired`. The three end states are final.

- **R-10 Unmatched requests are denied and recorded.** The proxy answers 403 at once
  (fail fast, the client retries); the row keeps `first_seen`/`last_seen` so
  parking the connection can be added later without a schema change. The name is never resolved
  before a rule allows it.
- **R-11 Dedupe on `(workspace_id, host, port)`:** at most one `requested` row per key (a partial unique
  index). A repeat updates `last_seen` and increments `attempts` on the existing row; it creates
  nothing. A request after the row ended (for example the allow it created later expired) opens a
  new row with a new id.
- **R-12 Pending rows are immutable:** `id`, `workspace_id`, `host`, `port` and
  `first_seen` never change after insert; ids are never reused. Only `last_seen`, `attempts`,
  `state`, `decided_at`, `decided_by` and `rule_id` change, and `state` only along the arrows above.
- **R-13 Per-workspace rate limit on new rows:** a token bucket per workspace, 60 new rows
  burst, refill 1 per second *(default)*, plus at most 500 open rows per workspace *(default)*. Over
  the limit the request is still denied, no row is written, and the workspace's `suppressed` counter
  goes up. One `pending_suppressed` audit record carries the count when suppression starts and
  every 60 s while it lasts; the inbox shows "N requests from <workspace> suppressed". Repeats of an
  open row (R-11) never consume tokens.
- **R-14 Local destinations** (the proxy applies this after resolving an allowed name; the engine supplies
  the match): an address in a local category with its toggle off is blocked and the block names
  the toggle, with no pending row. With the toggle on, only an `exact` allow
  counts: of the name, or of the resolved address itself (an exact IP rule admits that address,
  and only it). A suffix allow is treated as no match, and if no address is admitted the request
  goes pending for the exact name, unless the "wildcards reach local addresses"
  setting is on (global default off, per-workspace override *(default)*). The IP check only looks
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
  address. *(default)*: an address's own rules use R-6 precedence, so a workspace allow of the
  address beats a global deny of it. Numbered R-27 to keep the other numbers (and their test
  names) stable. *Added 2026-10-06: before, an IP deny was checked only on the wildcard
  path, so an exact name allow or an approval reached a denied address (firewall model,
  2026-10-04: false allows are very bad).*
- **R-15 Approve and deny** take a row id and four choices: effect (`allow`/`deny`), scope (`workspace`,
  the default, or `global`), pattern (`exact`, the default, or a suffix of the row's host that passes
  R-4) and expiry (permanent, the default, or a duration). This covers the inbox's four outcomes
  (allow/deny × this workspace/everyone). Defaults are never widened implicitly. Instead of a scope,
  the rule can go into a rule set the user made (R-38).
- **R-16 A decision is one transaction:** create the rule, set the row to `allowed`/`denied` with
  `rule_id`, `decided_at` and `decided_by`, and close every other `requested` row the new rule now
  decides (same workspace for a workspace rule, any workspace for a global one) the same way.
- **R-17 Stale ids are refused.** Approving or denying an unknown id or a row not in `requested`
  fails with an error naming the row's current state; nothing changes. A successful call returns
  the row as decided (workspace, host, port) and the rule created, so the CLI and UI can echo exactly
  what was approved.
- **R-18 The inbox groups by registrable domain** (public suffix list, as R-4) for display; grouping
  is derived, not stored, and never decides anything.

## 4. Sweeper

One background task, every 60 s *(default)* and at startup:

- **R-19** deletes rules with `expires_at <= now` and writes a `rule_expired` audit record holding
  the whole rule. Correctness never depends on it (R-7).
- **R-20** moves `requested` rows whose `last_seen` is older than 7 days *(default)* to `expired`.
- **R-21** on workspace deletion (not stop), deletes that workspace's rules (`rule_deleted`, reason
  `workspace_deleted`) and expires its open rows, in the same transaction as the deletion.
- **R-22** enforces the audit cap (R-26).

Sweeper work never holds a lock that a decision waits on for more than one short transaction.

## 5. Audit

Every decision, rule change and pending change is one record: a row in the SQLite `audit` table,
readable as JSONL (one record per line).

- **R-23 Serialised with `serde_json` only**, from one internally tagged enum
  (`"type": "..."`), per ADR 0002: `snake_case` fields, `ts` in epoch ms, `null` always written,
  never `untagged`, additive changes only. Control characters in any string come out escaped, so
  every line parses with `jq`. Lines are never rewritten: records written before the rename of
  sandbox to workspace carry `sandbox_id`, a rule scope `sandbox`, an origin `sandbox` and a
  reason `sandbox_deleted`, and read as `workspace_id`, `workspace`, `workspace` and
  `workspace_deleted`.
- **R-24 Record types** in `puddle-store`: `connection` (written by the proxy: `workspace_id`, `host`, `port`,
  `resolved_ip`, `decision` (`allow`, `deny`, `pending`, `blocked`), `reason` (`rule`, `no_rule`,
  `toggle:<category>`, `puddle_endpoint`, `ssh_unsupported`, `local_address`,
  `policy_unavailable`, `sni_mismatch`, `guest_tls_rejected`, `suppressed`, ...), `rule_id`, `rule_set` (the set whose entry decided, R-43), `pending_id`, `binding_id`, `injected`,
  `method` and `path` on terminated hosts, plain-HTTP requests and `CONNECT` tunnels that carry
  plain HTTP/1.x only, `bytes_up`, `bytes_down`), `pending_created`, `pending_decided`, `pending_expired`,
  `pending_suppressed` (`workspace_id`, `count`), `rule_created`, `rule_updated`, `rule_deleted`,
  `rule_expired` (with the full rule), `audit_trimmed` (`deleted_records`, `oldest_ts_kept`), and
  the rule set records of R-43. On a decrypted host whose client refuses puddle's certificate (it does not
  trust the workspace's CA) the decision stays what the rule said and the reason is `guest_tls_rejected`.
  The proxy writes one `connection` record per request whose destination it parsed, when the
  connection ends; a request refused before that (bad request, head too large or too slow, the
  workspace over its connection limit) has no destination and only goes to the log. `resolved_ip`
  is the address connected to (`null` if none was), and the bytes are counted on the guest side,
  proxy responses included.
  A `CONNECT` tunnel is decided like any request (rules see `(workspace, host, port)`, R-2), so
  `CONNECT host:80` and `GET http://host/` get the same decision and pending row. Node `fetch` and
  Yarn Berry send `http://` URLs that way. When a tunnel's first bytes are an HTTP/1.x request line,
  its record carries that request's `method` and `path` (first request only); the bytes are
  relayed unchanged. *Added 2026-10-06.*
  `upstream` names the company-proxy hop that carried the connection (`DIRECT` or `PROXY host:port`,
  never credentials; `null` when no upstream route is configured or nothing connected), and when
  it is a proxy hop `resolved_ip` is the address sent to the proxy, or `null` if the proxy was told
  the name (or this host could not resolve it). *Added 2026-10-07 (additive).*
  `origin` says whose connection it is: `workspace` (a workspace's, the default) or `puddle` (puddle's
  own, made on the host with no workspace: image pulls through the pull proxy). A `puddle` record has
  `workspace_id: null`, `reason: puddle_request` when the address guard let it through (or a block
  reason when it did not), no rule or pending row, and carries `upstream`, `resolved_ip` and the
  bytes like any other. The pull proxy writes one per pull whose destination it parsed; a request
  refused before that (no or wrong token) is only logged. Records written before `origin`
  existed have no such field and read as `workspace`. *Added 2026-10-07 (additive).*
- **R-25 No secrets.** Never header values, credential material, query strings or request bodies;
  credentials appear only as `binding_id` and `injected: true|false`. Every audit struct has a test
  that serialises it with canary values in every secret-bearing input and asserts the canary is
  absent.
- **R-26 Size caps.** One line is at most 4 KiB: `path` is cut to 1 KiB *(default)* with
  `path_truncated: true`, and any other oversize string field is cut the same way. Total audit is
  capped at 256 MiB *(default)*; the sweeper deletes the oldest records first and writes one
  `audit_trimmed` record per trim. Per workspace, `connection` records are limited to 200 per second
  *(default)*; the excess is counted and written as one `connection` record with
  `reason: suppressed` and a `count` per second. puddle's own connections (`origin: puddle`) share one limit of the same size.

- **R-28 Reading the audit with filters.** The API filters on the server, on stored columns and
  indexes (never by parsing JSON): `workspace`, `type`, `outcome`, `host_contains` (case-folded
  substring), `from` (inclusive) and `to` (exclusive) as epoch ms. All set filters must match.
  `host` is the record's host, or a rule record's pattern. `outcome` (`allow`, `deny`, `pending`,
  `blocked`, `expired`) exists for `connection` (its `decision`), `pending_created` (`pending`),
  `pending_decided` (`allow` or `deny`) and `pending_expired` (`expired`); every other record has
  none and never matches an `outcome` filter. `origin` (`workspace` or `puddle`) matches `connection`
  records only (a puddle record is one without a workspace); every other record has no origin and
  never matches. *`origin` added 2026-10-07.* Pages are at most 500 records: newest first, paged
  back with `before`, or oldest first from `after` to follow the tail.
- **R-29 Events.** After each commit the store emits, per change: `pending_opened` (a new open
  row), `pending_updated` (a repeat: `attempts`, `last_seen`), `pending_closed` (decided by a user
  or a rule, or expired: `state`, `rule_id`), `suppression_changed` (R-13: when it starts or ends,
  and at most twice a second while the count grows), `rules_changed` (any rule created, changed,
  deleted or expired, any rule set made, renamed, deleted or switched, and any change of System
  managed) and `audit_appended` (once per commit that wrote audit records, with the
  newest id). Events carry ids and counts, not decisions: a client that missed some refetches.
  A failed change emits nothing. `network_changed` (with the new network epoch) is not a store
  event: puddle sends it when the network or the system's proxy settings change, and a client
  refetches `GET /api/network-health`.

## 6. Name lookups from a guest that ignores the proxy settings

Some tools ignore `HTTPS_PROXY`: they resolve a name and connect to the answer. The guest agent
runs a stub DNS server for them; it answers each address query with a *stand-in address* from
`198.18.0.0/15` and asks the host about the name first, over the agent's `resolve` stream. The
connection to the stand-in is redirected to the agent, which sends `CONNECT name:port` like any
other client, so R-1 to R-14 apply to it unchanged. These rules say what the host answers to the
lookup. They are tested in `puddle-proxy` (`resolve`) and `puddle-e2e` (`stub_dns`), not in the
store.

- **R-30 A lookup writes nothing, except one `SRV` request (R-36).** It asks the rules engine
  without recording: no pending row, no audit record, no counter. The pending row and the deny
  come from the connection that follows (R-10), by name.
- **R-31 A name that no rule allows is not looked up.** An unmatched name, a denied name and a name
  blocked by itself (R-14: a toggle that is off, one of puddle's endpoints) all get a stand-in
  and cause **no** lookup on any resolver, so DNS is not a way out and a guest asking for many
  random names causes no resolver traffic. The connection that follows is refused with the
  usual reason. Record types other than `A` (`TXT`, `SRV`, `MX`) of such a name are answered
  with no data; R-36 adds one request for an `SRV` query of a name no rule matches.
- **R-32 An allowed name is resolved once, on the host.** If it resolves, the guest gets a
  stand-in. If the host's resolver says there is no such name, the guest gets `NXDOMAIN`, except
  under R-33; if the lookup itself fails (no resolver answered, the network is down) it gets
  `SERVFAIL` and the host logs why, never a cached "no such name". If every address it resolves to is refused by R-14, the guest still gets a stand-in:
  the connection says which toggle would allow it. The addresses never reach the guest, and the
  lookup does not constrain the connection, which resolves and checks again (R-14, R-27).
- **R-33 A name the host can't resolve goes to the company proxy by name, when one is in the
  route.** If an upstream proxy is in the route and sending unresolvable names to it is on (the
  default), an allowed name the host can't resolve, or whose lookup fails or times out, gets a
  stand-in too: on some networks only the proxy resolves internet names, and the proxy decides when
  the connection arrives. With no upstream proxy, or with that setting off, it is `NXDOMAIN` for a
  name that does not exist and `SERVFAIL` for a lookup that failed or timed out.
- **R-34 `SRV`, `TXT` and `MX` are looked up for allowed names only.** The rules decide the name
  without its leading service labels (`_mongodb._tcp.db.example.net` is decided as
  `db.example.net`), since a service label is not part of a host the user approves. The targets of
  `SRV` and `MX` records get stand-ins of their own in the answer. At most 16 records and 8 KiB of
  text are passed on.
- **R-35 A lookup is bounded.** The name must be a plain host name (labels of letters, digits, `-`
  and `_`, at most 253 characters) or the answer is "no such name" without a lookup. A workspace runs
  at most 32 host lookups at once and one agent session has at most 64 lookups open; over the cap
  the answer is "unavailable" (`SERVFAIL` in the guest). Each lookup has a timeout. An unreadable
  rules engine is "unavailable", never "not allowed".
- **R-36 An `SRV` query for a name no rule matches raises one request for its base name.** Clients
  such as `mongodb+srv://` ask for `SRV` first and give up on "no records" without ever
  connecting, so the user would never see them. The query `_mongodb._tcp.cluster.example.net`
  therefore opens one pending request for `cluster.example.net` (the leading service labels are
  stripped, as in R-34), with port 0 because the service's port is not known yet. It is
  deduplicated, limited and shown like any other pending request (R-11, R-13), and the answer is
  no data until the user decides; once the name is allowed the same query is looked up (R-34).
  It applies to `SRV` only: `TXT`, `MX` and address queries still raise nothing. A name a deny
  rule matches, a name blocked by itself (R-14) and a name that is not a plain host name raise
  nothing.

The stub answers names that can never be a connect target itself (reverse zones, names that end in
a number) with `NXDOMAIN`. Every other name, including single labels and zones such as `.local` or
`.internal`, is decided by the rules like any other, so a company's intranet names work once
allowed. Every other record type (`AAAA`, `HTTPS`, ...) gets no data, so dual-stack
clients use the stand-in at once.

## 7. Rule sets and System managed

A **rule set** is a named bundle of entries switched on or off as one. *Built-in* sets ship with
puddle; the user makes *their own*. **System managed** is a separate, read-only list: the hosts
puddle allows because of choices the user made (which browser editor server, direct SSH), each
with its reason. The user's own global and workspace rules (§1) are called *own rules* below. These
rules are tested in `puddle-store` (`rule_sets_spec`, the engine's property tests), the proxy and
the API. *Added 2026-10-08.*

- **R-36 Built-in sets ship off, only allow, and update with puddle.** A built-in set is data in
  puddle (an id `builtin:<slug>`, a name, a description, entries with a note each), checked at
  build time against R-4 and for duplicates. It is read-only and never copied into the database, so
  an update of puddle updates it. puddle ships no deny list: built-in entries only allow. Each
  ships switched off. When an update changes a set's entries, the store writes one
  `rule_set_changed` record (`added`, `removed`) when it opens, and the set shows when it changed.
- **R-37 Switches.** Every set has a switch for every workspace and an override per workspace, each
  on, off or unset; unset passes to the next level (the workspace's, then every workspace's, then the
  set's default: built-in sets off, the user's own sets on). A switch applies to the next request
  (R-8). Switching a set on closes the open requests it now decides, like a new rule (R-16), and
  says which. System managed has no switch.
- **R-38 Sets the user makes.** A set has a name (1 to 64 characters, unique among all sets,
  case-insensitive), a description, and entries that are ordinary rules with the scope `set`
  (exact or suffix, allow or deny, with an optional expiry, R-7). Entries are added like any rule,
  or by approving or denying a pending request **into the set** (R-15): the set must be on for
  the request's workspace, or the decision is refused (it would not allow the request). Deleting a
  set deletes its entries (`rule_deleted`, reason `set_deleted`) and its switches.
- **R-39 Precedence: a set never opens what an own rule closes.** For a request, the own rules
  are ranked as R-6 and the entries of the sets that are on for its workspace are ranked by pattern
  specificity, then deny over allow. When an own rule matches, it decides, unless a set's deny is
  strictly more specific than it. When no own rule matches, the most specific set entry decides,
  deny over allow. So a set's allow only fills gaps; a set's deny acts like a rule at its level of
  detail, ranked below an own rule of the same detail. Examples: a global own deny of
  `*.visualstudio.com` beats System managed's `update.code.visualstudio.com`; an own allow of
  `*.example.com` loses to a set's deny of `ads.example.com`, and an own exact allow of
  `ads.example.com` wins again. Between two sets the same order applies.
- **R-40 System managed is shown, with reasons.** The Rules screen lists every System managed
  host with its reason in words and where it applies (every workspace or one). Nothing in it is
  stored as a rule or hidden. To block one of its hosts, the user adds an own deny (R-39); to
  remove the reason, the user changes the choice behind it.
- **R-41 System managed follows the setup.** puddle derives it from the settings at start and
  after every settings or consent change, and stores only the reasons (so a restart with the same
  setup changes and records nothing):

  | Setting | Hosts | Applies to |
  |---|---|---|
  | The browser editor runs Microsoft's VS Code server (consent granted) | `update.code.visualstudio.com`, `vscode.download.prss.microsoft.com`, `marketplace.visualstudio.com`, `*.gallery.vsassets.io`, `*.gallerycdn.vsassets.io` | every workspace |
  | The browser editor runs the bundled code-server (the default) | `open-vsx.org`, `openvsx.eclipsecontent.org` | every workspace |
  | Direct SSH is on for a workspace | the five Microsoft hosts | that workspace |

  Telemetry, experiment and certificate-status hosts are not in it: they are ordinary traffic
  (R-1). When the reasons change, one `system_managed_changed` record per scope says which reasons
  were added and removed, and open requests the new hosts decide are closed by `system` (R-37).
  Direct SSH is the workspace's effective `direct_ssh` setting (its own value, else the global
  default).
- **R-42 A set's allow reaches a local destination only like a wildcard.** After resolving a name
  a set allowed, an address in a local category counts as reached by a wildcard rule (R-14): with
  "wildcards reach local addresses" off, it needs an own exact allow of the name or the address,
  and goes pending for the exact name otherwise. A set's deny of an IP literal excludes that
  address like an own one (R-27).
- **R-43 Rule set records.** `rule_set_created`, `rule_set_updated` (rename), `rule_set_deleted`
  (each with the set and the actor), `rule_set_switched` (`set_id`, `workspace_id` or `null` for
  every workspace, `enabled` true, false or `null`, actor), `rule_set_changed` (R-36) and
  `system_managed_changed` (R-41). A connection decided by a set's entry has `reason: rule`, the
  entry's `rule_id` (`null` for built-in and System managed entries) and `rule_set`; a pending
  row closed by one records the set in `rule_set`. A refusal by a set's deny carries
  `x-puddle-rule-set` next to `x-puddle-rule`.

## 8. Out of scope here

The AI judge (no field or placeholder until its flow is designed), subscribed lists (a rule set
fetched from a URL), path rules (after v1), port rules, and the "Dangerous settings" unblock of
puddle's endpoints (later). Address classification, name normalisation and the 403 body belong to
the proxy and `puddle-netpolicy`; the API and CLI shape of R-15 to `puddle-api` and `puddle`.
